#!/usr/bin/env python3
"""
UP-AirQuality -> MQTT bridge for Home Assistant, with LED control.

  1. logs in (cookie auth + CSRF) and reads /bootstrap for the full initial
     state + the current lastUpdateId,
  2. opens the Protect updates WebSocket and applies the binary-framed deltas
     as they arrive, republishing readings to MQTT on every airQuality change,
  3. exposes the LED ring as controllable Home Assistant entities:
       - number  "LED Brightness"  (0-100)  -> airQualitySettings.ringLedBrightness
       - select  "LED Metric"      (AQI/CO2) -> airQualitySettings.ringLedMetric
     Commands from HA are PATCHed back to the sensor.

Protect's WS "updates" packet = two frames, each: 8-byte header + payload.
Header: [type, format, deflated, _, size:uint32-be]. format 1 = JSON, deflated
means zlib. Frame 0 is the action ({action, modelKey, id, ...}), frame 1 is the
delta of changed fields.

Env vars: PROTECT_HOST / PROTECT_USER / PROTECT_PASS, MQTT_HOST / MQTT_PORT /
MQTT_USER / MQTT_PASS, DISCOVERY_PREFIX. Event-driven — no polling interval.
"""

import base64
import http.cookiejar
import json
import os
import ssl
import struct
import sys
import time
import urllib.request
import zlib

import paho.mqtt.client as mqtt
import websocket  # websocket-client

# metric key -> (HA name, device_class | None, unit | None). Unknown future
# keys (e.g. a firmware that adds "nox") still get published as raw state.
METRICS = {
    "aqi":         ("AQI",         "aqi",            None),
    "vape":        ("Vape Index",  None,             None),
    "co2":         ("CO2",         "carbon_dioxide", "ppm"),
    "tvoc":        ("TVOC",        None,             None),
    "voc":         ("VOC Index",   None,             None),
    "nox":         ("NOx Index",   None,             None),
    "pm1p0":       ("PM1.0",       "pm1",            "µg/m³"),
    "pm2p5":       ("PM2.5",       "pm25",           "µg/m³"),
    "pm4p0":       ("PM4.0",       None,             "µg/m³"),
    "pm10p0":      ("PM10",        "pm10",           "µg/m³"),
    "temperature": ("Temperature", "temperature",    "°C"),
    "humidity":    ("Humidity",    "humidity",       "%"),
}


def slug(mac):
    return mac.replace(":", "").lower()


def first_aq_sensor(sensors):
    """Return (device, airQuality dict) for the first UP-AirQuality found."""
    if not isinstance(sensors, list):
        sensors = sensors.get("data") or sensors.get("sensors") or [sensors]
    for s in sensors:
        aq = s.get("airQuality")
        if isinstance(aq, dict) and aq:
            return s, aq
    return None, None


# ringLedMetric integer <-> HA select option.
# Verified against the UniFi app: 0 = CO2, 1 = Air Quality.
LED_METRIC_OPTIONS = {"Air Quality": 1, "CO2": 0}
LED_METRIC_REVERSE = {v: k for k, v in LED_METRIC_OPTIONS.items()}

# Per-metric alert thresholds live at
# airQualitySettings.<metric>Settings.{low,high}Threshold.
# (label, unit, min, max, step) drives the HA number entities.
THRESHOLD_METRICS = {
    "aqi":         ("AQI",         None,    0,   500,  1),
    "vape":        ("Vape",        None,    0,   100,  1),
    "co2":         ("CO2",         "ppm",   0, 40000, 10),
    "tvoc":        ("TVOC",        None,    0,  1000,  1),
    "voc":         ("VOC Index",   None,    0,   500,  1),
    "pm1p0":       ("PM1.0",       "µg/m³", 0,  1000,  1),
    "pm2p5":       ("PM2.5",       "µg/m³", 0,  1000,  1),
    "pm4p0":       ("PM4.0",       "µg/m³", 0,  1000,  1),
    "pm10p0":      ("PM10",        "µg/m³", 0,  1000,  1),
    "humidity":    ("Humidity",    "%",     0,   100,  1),
    "temperature": ("Temperature", "°C",  -20,    60,  1),
}
THRESHOLD_BOUNDS = {"low": "lowThreshold", "high": "highThreshold"}


def env(name, default=None, required=False):
    val = os.environ.get(name, default)
    if required and not val:
        sys.exit(f"Missing required env var: {name}")
    return val


def _ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _csrf_from_token(token):
    """UniFi OS TOKEN is a JWT whose payload carries csrfToken."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)  # pad base64
        return json.loads(base64.urlsafe_b64decode(payload)).get("csrfToken")
    except Exception:
        return None


def login_and_bootstrap(host, user, pw):
    """Return (token_cookie_value, csrf_token, bootstrap_dict)."""
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=_ctx()),
        urllib.request.HTTPCookieProcessor(jar),
    )
    login = json.dumps({"username": user, "password": pw}).encode()
    req = urllib.request.Request(
        f"https://{host}/api/auth/login",
        data=login,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    resp = opener.open(req, timeout=20)
    csrf = resp.headers.get("X-CSRF-Token") or resp.headers.get("X-Csrf-Token")
    resp.read()

    token = next((c.value for c in jar if c.name == "TOKEN"), None)
    if not token:
        sys.exit("Login succeeded but no TOKEN cookie returned")
    if not csrf:
        csrf = _csrf_from_token(token)  # fall back to the JWT payload

    req = urllib.request.Request(
        f"https://{host}/proxy/protect/api/bootstrap",
        headers={"Accept": "application/json"},
    )
    bootstrap = json.loads(opener.open(req, timeout=20).read())
    return token, csrf, bootstrap


def patch_sensor(host, token, csrf, sensor_id, body):
    """PATCH a partial settings object onto the sensor."""
    req = urllib.request.Request(
        f"https://{host}/proxy/protect/api/sensors/{sensor_id}",
        data=json.dumps(body).encode(),
        method="PATCH",
        headers={
            "Content-Type": "application/json",
            "Cookie": f"TOKEN={token}",
            "X-CSRF-Token": csrf or "",
        },
    )
    urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=_ctx())
    ).open(req, timeout=20).read()


def decode_packet(data):
    """Decode a Protect WS binary packet into a list of JSON frames."""
    frames = []
    offset = 0
    while offset + 8 <= len(data):
        pformat = data[offset + 1]
        deflated = data[offset + 2]
        size = struct.unpack(">I", data[offset + 4:offset + 8])[0]
        payload = data[offset + 8:offset + 8 + size]
        offset += 8 + size
        if deflated:
            payload = zlib.decompress(payload)
        if pformat == 1:
            frames.append(json.loads(payload))
        else:
            frames.append(payload)
    return frames


def deep_merge(base, delta):
    for k, v in delta.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            deep_merge(base[k], v)
        else:
            base[k] = v


def publish_discovery(client, prefix, device, aq):
    """Publish one HA discovery config per present air-quality metric.
    Returns (state_topic, avail_topic)."""
    mac = slug(device.get("mac", "unknown"))
    node = f"protect_air_quality_{mac}"
    state_topic = f"up_airquality/{mac}/state"
    avail_topic = f"up_airquality/{mac}/availability"

    dev_block = {
        "identifiers": [f"up_airquality_{mac}"],
        "name": device.get("name", "Protect Air Quality"),
        "manufacturer": "Ubiquiti",
        "model": device.get("type", "UP-AirQuality"),
        "sw_version": device.get("firmwareVersion"),
    }

    for key in aq:
        meta = METRICS.get(key)
        if not meta:
            continue  # unknown key we don't model; skip discovery (still in state)
        name, device_class, unit = meta
        cfg = {
            "name": name,
            "unique_id": f"up_aq_{mac}_{key}",
            "object_id": f"{node}_{key}",
            "state_topic": state_topic,
            "value_template": f"{{{{ value_json.{key} }}}}",
            # Expose the per-metric band (e.g. "neutral") as a 'status' attribute.
            "json_attributes_topic": state_topic,
            "json_attributes_template":
                f"{{{{ {{'status': value_json.{key}_status}} | tojson }}}}",
            "availability_topic": avail_topic,
            "state_class": "measurement",
            "device": dev_block,
        }
        if device_class:
            cfg["device_class"] = device_class
        if unit:
            cfg["unit_of_measurement"] = unit
        client.publish(f"{prefix}/sensor/{node}/{key}/config",
                       json.dumps(cfg), qos=1, retain=True)
    return state_topic, avail_topic


def publish_control_discovery(client, prefix, device, avail_topic):
    """Publish HA discovery for the LED control entities. Returns topic dict."""
    mac = slug(device.get("mac", "unknown"))
    node = f"protect_air_quality_{mac}"
    base = f"up_airquality/{mac}"
    dev_block = {
        "identifiers": [f"up_airquality_{mac}"],  # must match sensor entities
        "name": device.get("name", "Protect Air Quality"),
        "manufacturer": "Ubiquiti",
        "model": device.get("type", "UP-AirQuality"),
        "sw_version": device.get("firmwareVersion"),
    }
    t = {
        "brightness_cmd":   f"{base}/led_brightness/set",
        "brightness_state": f"{base}/led_brightness/state",
        "metric_cmd":       f"{base}/led_metric/set",
        "metric_state":     f"{base}/led_metric/state",
        "status_cmd":       f"{base}/status_light/set",
        "status_state":     f"{base}/status_light/state",
        "night_cmd":        f"{base}/night_mode/set",
        "night_state":      f"{base}/night_mode/state",
        "night_bri_cmd":    f"{base}/night_brightness/set",
        "night_bri_state":  f"{base}/night_brightness/state",
        "fw_version_state": f"{base}/firmware_version/state",
        "fw_update_state":  f"{base}/firmware_update/state",
        "base":             base,
    }

    brightness = {
        "name": "LED Brightness",
        "unique_id": f"up_aq_{mac}_led_brightness",
        "object_id": f"{node}_led_brightness",
        "command_topic": t["brightness_cmd"],
        "state_topic": t["brightness_state"],
        "availability_topic": avail_topic,
        "min": 0, "max": 100, "step": 1, "mode": "slider",
        "icon": "mdi:brightness-6",
        "entity_category": "config",
        "device": dev_block,
    }
    metric = {
        "name": "LED Metric",
        "unique_id": f"up_aq_{mac}_led_metric",
        "object_id": f"{node}_led_metric",
        "command_topic": t["metric_cmd"],
        "state_topic": t["metric_state"],
        "availability_topic": avail_topic,
        "options": list(LED_METRIC_OPTIONS),
        "icon": "mdi:led-on",
        "entity_category": "config",
        "device": dev_block,
    }
    status_light = {
        "name": "Status Light",
        "unique_id": f"up_aq_{mac}_status_light",
        "object_id": f"{node}_status_light",
        "command_topic": t["status_cmd"],
        "state_topic": t["status_state"],
        "availability_topic": avail_topic,
        "payload_on": "ON", "payload_off": "OFF",
        "icon": "mdi:led-on",
        "entity_category": "config",
        "device": dev_block,
    }
    night_mode = {
        "name": "Night Mode",
        "unique_id": f"up_aq_{mac}_night_mode",
        "object_id": f"{node}_night_mode",
        "command_topic": t["night_cmd"],
        "state_topic": t["night_state"],
        "availability_topic": avail_topic,
        "payload_on": "ON", "payload_off": "OFF",
        "icon": "mdi:weather-night",
        "entity_category": "config",
        "device": dev_block,
    }
    night_brightness = {
        "name": "Night Mode Brightness",
        "unique_id": f"up_aq_{mac}_night_brightness",
        "object_id": f"{node}_night_brightness",
        "command_topic": t["night_bri_cmd"],
        "state_topic": t["night_bri_state"],
        "availability_topic": avail_topic,
        "min": 0, "max": 100, "step": 1, "mode": "slider",
        "icon": "mdi:brightness-3",
        "entity_category": "config",
        "device": dev_block,
    }
    client.publish(f"{prefix}/number/{node}/led_brightness/config",
                   json.dumps(brightness), qos=1, retain=True)
    client.publish(f"{prefix}/select/{node}/led_metric/config",
                   json.dumps(metric), qos=1, retain=True)
    client.publish(f"{prefix}/switch/{node}/status_light/config",
                   json.dumps(status_light), qos=1, retain=True)
    client.publish(f"{prefix}/switch/{node}/night_mode/config",
                   json.dumps(night_mode), qos=1, retain=True)
    fw_version = {
        "name": "Firmware Version",
        "unique_id": f"up_aq_{mac}_fw_version",
        "object_id": f"{node}_firmware_version",
        "state_topic": t["fw_version_state"],
        "availability_topic": avail_topic,
        "icon": "mdi:chip",
        "entity_category": "diagnostic",
        "device": dev_block,
    }
    fw_update = {
        "name": "Firmware Update Available",
        "unique_id": f"up_aq_{mac}_fw_update",
        "object_id": f"{node}_firmware_update",
        "state_topic": t["fw_update_state"],
        "availability_topic": avail_topic,
        "payload_on": "ON", "payload_off": "OFF",
        "device_class": "update",
        "entity_category": "diagnostic",
        "device": dev_block,
    }
    client.publish(f"{prefix}/number/{node}/night_brightness/config",
                   json.dumps(night_brightness), qos=1, retain=True)
    client.publish(f"{prefix}/sensor/{node}/firmware_version/config",
                   json.dumps(fw_version), qos=1, retain=True)
    client.publish(f"{prefix}/binary_sensor/{node}/firmware_update/config",
                   json.dumps(fw_update), qos=1, retain=True)

    for metric, (label, unit, mn, mx, step) in THRESHOLD_METRICS.items():
        for bound in ("low", "high"):
            cfg = {
                "name": f"{label} {bound.capitalize()} Threshold",
                "unique_id": f"up_aq_{mac}_{metric}_{bound}_thresh",
                "object_id": f"{node}_{metric}_{bound}_threshold",
                "command_topic": f"{base}/thresh/{metric}/{bound}/set",
                "state_topic": f"{base}/thresh/{metric}/{bound}/state",
                "availability_topic": avail_topic,
                "min": mn, "max": mx, "step": step, "mode": "box",
                "icon": "mdi:tune-variant",
                "entity_category": "config",
                "device": dev_block,
            }
            if unit:
                cfg["unit_of_measurement"] = unit
            client.publish(
                f"{prefix}/number/{node}/{metric}_{bound}_threshold/config",
                json.dumps(cfg), qos=1, retain=True)
    return t


def publish_control_state(client, topics, device):
    """Mirror the sensor's current LED settings to the control state topics."""
    aqs = device.get("airQualitySettings") or {}
    led = device.get("ledSettings") or {}
    b = aqs.get("ringLedBrightness")
    m = aqs.get("ringLedMetric")
    if b is not None:
        client.publish(topics["brightness_state"], b, qos=1, retain=True)
    if m is not None:
        client.publish(topics["metric_state"],
                       LED_METRIC_REVERSE.get(m, "Air Quality"), qos=1, retain=True)
    if led.get("isEnabled") is not None:
        client.publish(topics["status_state"],
                       "ON" if led["isEnabled"] else "OFF", qos=1, retain=True)
    if aqs.get("nightModeEnabled") is not None:
        client.publish(topics["night_state"],
                       "ON" if aqs["nightModeEnabled"] else "OFF", qos=1, retain=True)
    if aqs.get("nightModeBrightness") is not None:
        client.publish(topics["night_bri_state"],
                       aqs["nightModeBrightness"], qos=1, retain=True)
    base = topics.get("base")
    if base:  # per-metric thresholds (publish only the ones that are set)
        for metric in THRESHOLD_METRICS:
            ms = aqs.get(f"{metric}Settings") or {}
            for bound, key in THRESHOLD_BOUNDS.items():
                v = ms.get(key)
                if v is not None:
                    client.publish(f"{base}/thresh/{metric}/{bound}/state",
                                   v, qos=1, retain=True)


def publish_diag_state(client, topics, device):
    """Mirror firmware version + update-available to their state topics."""
    fw = device.get("firmwareVersion")
    latest = device.get("latestFirmwareVersion")
    fw_state = device.get("fwUpdateState")
    if fw:
        client.publish(topics["fw_version_state"], fw, qos=1, retain=True)
    update_avail = (fw_state not in (None, "upToDate")) or \
                   (bool(latest) and bool(fw) and latest != fw)
    client.publish(topics["fw_update_state"],
                   "ON" if update_avail else "OFF", qos=1, retain=True)


def main():
    host = env("PROTECT_HOST", required=True)
    user = env("PROTECT_USER", required=True)
    pw = env("PROTECT_PASS", required=True)
    mqtt_host = env("MQTT_HOST", required=True)
    mqtt_port = int(env("MQTT_PORT", "1883"))
    mqtt_user = env("MQTT_USER")
    mqtt_pass = env("MQTT_PASS")
    prefix = env("DISCOVERY_PREFIX", "homeassistant")

    # Shared mutable context so the MQTT command callback always uses the
    # current token/csrf/topics (both refresh on every reconnect).
    ctx = {"host": host, "token": None, "csrf": None, "sensor_id": None,
           "device": None, "topics": None}

    def on_mqtt_message(client, userdata, msg):
        topics = ctx["topics"]
        if not topics:
            return
        payload = msg.payload.decode(errors="replace").strip()
        try:
            if msg.topic == topics["brightness_cmd"]:
                val = max(0, min(100, int(float(payload))))
                patch_sensor(ctx["host"], ctx["token"], ctx["csrf"],
                             ctx["sensor_id"], {"airQualitySettings":
                                                {"ringLedBrightness": val}})
                ctx["device"]["airQualitySettings"]["ringLedBrightness"] = val
                client.publish(topics["brightness_state"], val, qos=1, retain=True)
                print(f"LED brightness -> {val}", flush=True)
            elif msg.topic == topics["metric_cmd"]:
                if payload not in LED_METRIC_OPTIONS:
                    print(f"Ignoring unknown metric option: {payload}", flush=True)
                    return
                val = LED_METRIC_OPTIONS[payload]
                patch_sensor(ctx["host"], ctx["token"], ctx["csrf"],
                             ctx["sensor_id"], {"airQualitySettings":
                                                {"ringLedMetric": val}})
                ctx["device"]["airQualitySettings"]["ringLedMetric"] = val
                client.publish(topics["metric_state"], payload, qos=1, retain=True)
                print(f"LED metric -> {payload} ({val})", flush=True)
            elif msg.topic == topics["status_cmd"]:
                on = payload.upper() == "ON"
                patch_sensor(ctx["host"], ctx["token"], ctx["csrf"],
                             ctx["sensor_id"], {"ledSettings": {"isEnabled": on}})
                ctx["device"].setdefault("ledSettings", {})["isEnabled"] = on
                client.publish(topics["status_state"], payload.upper(),
                               qos=1, retain=True)
                print(f"Status light -> {payload.upper()}", flush=True)
            elif msg.topic == topics["night_cmd"]:
                on = payload.upper() == "ON"
                patch_sensor(ctx["host"], ctx["token"], ctx["csrf"],
                             ctx["sensor_id"],
                             {"airQualitySettings": {"nightModeEnabled": on}})
                ctx["device"]["airQualitySettings"]["nightModeEnabled"] = on
                client.publish(topics["night_state"], payload.upper(),
                               qos=1, retain=True)
                print(f"Night mode -> {payload.upper()}", flush=True)
            elif msg.topic == topics["night_bri_cmd"]:
                val = max(0, min(100, int(float(payload))))
                patch_sensor(ctx["host"], ctx["token"], ctx["csrf"],
                             ctx["sensor_id"],
                             {"airQualitySettings": {"nightModeBrightness": val}})
                ctx["device"]["airQualitySettings"]["nightModeBrightness"] = val
                client.publish(topics["night_bri_state"], val, qos=1, retain=True)
                print(f"Night mode brightness -> {val}", flush=True)
            elif "/thresh/" in msg.topic and msg.topic.endswith("/set"):
                # up_airquality/<mac>/thresh/<metric>/<bound>/set
                parts = msg.topic.split("/")
                metric, bound = parts[3], parts[4]
                if metric not in THRESHOLD_METRICS or bound not in THRESHOLD_BOUNDS:
                    return
                fval = float(payload)
                val = int(fval) if fval.is_integer() else fval
                key = THRESHOLD_BOUNDS[bound]
                patch_sensor(ctx["host"], ctx["token"], ctx["csrf"],
                             ctx["sensor_id"],
                             {"airQualitySettings": {f"{metric}Settings": {key: val}}})
                aqs = ctx["device"].setdefault("airQualitySettings", {})
                aqs.setdefault(f"{metric}Settings", {})[key] = val
                client.publish(f"{topics['base']}/thresh/{metric}/{bound}/state",
                               val, qos=1, retain=True)
                print(f"Threshold {metric}.{bound} -> {val}", flush=True)
        except Exception as e:
            print(f"command error on {msg.topic}: {e}", flush=True)

    def command_subscriptions(topics):
        subs = [(topics[k], 0) for k in
                ("brightness_cmd", "metric_cmd", "status_cmd",
                 "night_cmd", "night_bri_cmd")]
        subs.append((f"{topics['base']}/thresh/+/+/set", 0))  # all thresholds
        return subs

    def on_connect(client, userdata, flags, reason_code, properties):
        # Re-subscribe on every (re)connect once we know the topics.
        topics = ctx["topics"]
        if topics:
            client.subscribe(command_subscriptions(topics))
            print("Subscribed to LED command topics", flush=True)

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_message = on_mqtt_message
    client.on_connect = on_connect
    if mqtt_user:
        client.username_pw_set(mqtt_user, mqtt_pass)
    client.connect(mqtt_host, mqtt_port, keepalive=60)
    client.loop_start()
    print(f"Connected to MQTT {mqtt_host}:{mqtt_port}", flush=True)

    avail_topic = None
    failures = 0  # consecutive failures, drives exponential backoff
    while True:
        connected_at = None
        try:
            token, csrf, bootstrap = login_and_bootstrap(host, user, pw)
            device, aq = first_aq_sensor(bootstrap.get("sensors", []))
            if not aq:
                print("No UP-AirQuality sensor in bootstrap; retrying", flush=True)
                failures += 1
                time.sleep(min(5 * 2 ** failures, 300))
                continue
            sensor_id = device.get("id")
            last_update_id = bootstrap.get("lastUpdateId", "")
            print(f"Sensor id={sensor_id}  lastUpdateId={last_update_id}", flush=True)

            state_topic, avail_topic = publish_discovery(client, prefix, device, aq)
            client.will_set(avail_topic, "offline", qos=1, retain=True)

            ctx.update(token=token, csrf=csrf, sensor_id=sensor_id, device=device)
            ctx["topics"] = publish_control_discovery(client, prefix, device,
                                                       avail_topic)
            # subscribe now (on_connect only fires on MQTT (re)connect)
            client.subscribe(command_subscriptions(ctx["topics"]))

            def publish_state():
                payload = {}
                for k, v in device["airQuality"].items():
                    if isinstance(v, dict):
                        payload[k] = v.get("value")
                        payload[f"{k}_status"] = v.get("status")
                client.publish(state_topic, json.dumps(payload), qos=0, retain=False)
                client.publish(avail_topic, "online", qos=1, retain=True)
                print(f"Published: {payload}", flush=True)

            publish_state()                          # seed readings
            publish_control_state(client, ctx["topics"], device)  # seed LED state
            publish_diag_state(client, ctx["topics"], device)     # seed firmware

            def on_message(ws, message):
                if not isinstance(message, (bytes, bytearray)):
                    return
                try:
                    frames = decode_packet(message)
                except Exception as e:
                    print(f"decode error: {e}", flush=True)
                    return
                if len(frames) < 2:
                    return
                action, delta = frames[0], frames[1]
                if action.get("modelKey") != "sensor" or action.get("id") != sensor_id:
                    return
                if "airQuality" in delta:
                    deep_merge(device, delta)
                    publish_state()
                if "airQualitySettings" in delta or "ledSettings" in delta:
                    deep_merge(device, delta)  # changed elsewhere (app)
                    publish_control_state(client, ctx["topics"], device)
                if any(k in delta for k in ("firmwareVersion", "fwUpdateState",
                                            "latestFirmwareVersion")):
                    deep_merge(device, delta)
                    publish_diag_state(client, ctx["topics"], device)

            def on_open(ws):
                nonlocal connected_at
                connected_at = time.time()

            def on_error(ws, err):
                print(f"WS error: {err}", flush=True)

            def on_close(ws, code, msg):
                print(f"WS closed: {code} {msg}", flush=True)

            ws_url = (f"wss://{host}/proxy/protect/ws/updates"
                      f"?lastUpdateId={last_update_id}")
            print(f"Connecting WS: {ws_url}", flush=True)
            ws = websocket.WebSocketApp(
                ws_url, header=[f"Cookie: TOKEN={token}"],
                on_open=on_open, on_message=on_message,
                on_error=on_error, on_close=on_close,
            )
            ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE}, ping_interval=30)
        except Exception as e:
            print(f"loop error: {e}", flush=True)
        finally:
            if avail_topic:
                client.publish(avail_topic, "offline", qos=1, retain=True)

        # Exponential backoff. Reset only if the WS stayed up a healthy while,
        # so a failing login can't turn into a 5s reconnect/login storm.
        if connected_at and (time.time() - connected_at) > 60:
            failures = 0
        else:
            failures += 1
        delay = min(5 * 2 ** failures, 300)
        print(f"Reconnecting in {delay}s (failures={failures})", flush=True)
        time.sleep(delay)


if __name__ == "__main__":
    main()
