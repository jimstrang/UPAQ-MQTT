# UP-AirQuality -> MQTT bridge.
FROM python:3.13-slim

RUN pip install --no-cache-dir paho-mqtt==2.1.0 websocket-client==1.8.0

WORKDIR /app
COPY bridge.py /app/

ENTRYPOINT ["python3", "bridge.py"]
