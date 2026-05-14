# =============================================================================
# devices/temperature_sensor.py — Simulated Temperature Sensor
# =============================================================================
# This script simulates an IoT temperature sensor that:
#   1. Connects to the MQTT broker
#   2. Periodically publishes a JSON temperature reading
#   3. Handles connection errors gracefully
#
# In a real IoT deployment, this would run on a microcontroller (ESP32, RPi)
# connected to a physical thermistor or DS18B20 sensor.
# =============================================================================

import paho.mqtt.client as mqtt  # MQTT client library
import json                       # For formatting our message as JSON
import time                       # For the publish interval delay
import random                     # To simulate realistic temperature fluctuation
import sys
import os

# ── Add parent directory to path so we can import config.py ──────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# ── DEVICE IDENTITY ──────────────────────────────────────────────────────────
DEVICE_ID    = "temp-sensor-01"
DEVICE_ROOM  = "living_room"

# ── SIMULATED SENSOR STATE ───────────────────────────────────────────────────
# We start at a realistic room temperature and fluctuate ± a small amount
# to simulate real sensor noise.
current_temp = 21.5     # Starting temperature in Celsius


# ─────────────────────────────────────────────────────────────────────────────
# MQTT CALLBACK: on_connect
# Called automatically when the client successfully connects to the broker.
# 'rc' is the result code: 0 means success.
# ─────────────────────────────────────────────────────────────────────────────
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"[{DEVICE_ID}] ✅ Connected to MQTT broker at "
              f"{config.BROKER_HOST}:{config.BROKER_PORT}")
    else:
        # Result codes: 1=wrong protocol, 2=bad client ID, 3=server unavailable
        print(f"[{DEVICE_ID}] ❌ Connection failed with code {rc}")


# ─────────────────────────────────────────────────────────────────────────────
# MQTT CALLBACK: on_disconnect
# Called when the connection is lost (e.g., broker shuts down).
# ─────────────────────────────────────────────────────────────────────────────
def on_disconnect(client, userdata, rc):
    if rc != 0:
        print(f"[{DEVICE_ID}] ⚠️  Unexpected disconnection (code {rc}). "
              f"Will attempt reconnect...")


# ─────────────────────────────────────────────────────────────────────────────
# FUNCTION: simulate_temperature
# Returns a slightly varied temperature each call to mimic real sensor drift.
# ─────────────────────────────────────────────────────────────────────────────
def simulate_temperature():
    global current_temp
    # Add a small random delta between -0.5 and +0.5 degrees
    delta = random.uniform(-0.5, 0.5)
    current_temp = round(current_temp + delta, 2)
    # Clamp to a realistic indoor range to avoid drift too far
    current_temp = max(18.0, min(30.0, current_temp))
    return current_temp


# ─────────────────────────────────────────────────────────────────────────────
# FUNCTION: build_payload
# Creates the JSON message we'll publish to the broker.
# Using JSON is standard in IoT — it's human-readable and easy to parse.
# ─────────────────────────────────────────────────────────────────────────────
def build_payload(temperature):
    payload = {
        "device_id":   DEVICE_ID,
        "device_type": "temperature_sensor",
        "room":        DEVICE_ROOM,
        "temperature": temperature,
        "unit":        "celsius",
        "timestamp":   time.time()      # Unix epoch timestamp
    }
    return json.dumps(payload)  # Convert Python dict → JSON string


# ─────────────────────────────────────────────────────────────────────────────
# MAIN: Set up MQTT client and start publishing loop
# ─────────────────────────────────────────────────────────────────────────────
def main():
    # Create a new MQTT client instance
    # client_id must be unique on the broker — we use our device ID
    client = mqtt.Client(client_id=DEVICE_ID)

    # Register our callback functions
    client.on_connect    = on_connect
    client.on_disconnect = on_disconnect

    print(f"[{DEVICE_ID}] 🔌 Connecting to broker {config.BROKER_HOST}:{config.BROKER_PORT}...")

    try:
        client.connect(config.BROKER_HOST, config.BROKER_PORT, config.BROKER_KEEPALIVE)
    except ConnectionRefusedError:
        print(f"[{DEVICE_ID}] ❌ Could not connect. Is Mosquitto running?")
        print(f"    Run: sudo systemctl start mosquitto")
        sys.exit(1)

    # Start the background network loop (handles reconnections automatically)
    client.loop_start()

    # ── MAIN PUBLISH LOOP ─────────────────────────────────────────────────
    print(f"[{DEVICE_ID}] 📡 Starting publish loop every "
          f"{config.TEMP_PUBLISH_INTERVAL}s...")
    try:
        while True:
            temp = simulate_temperature()
            payload = build_payload(temp)

            # QoS 0: "fire and forget" — typical for frequent sensor readings
            # QoS 1: "at least once" — use for critical alerts
            result = client.publish(config.TOPIC_TEMPERATURE, payload, qos=0)

            if result.rc == mqtt.MQTT_ERR_SUCCESS:
                print(f"[{DEVICE_ID}] 🌡️  Published: {temp}°C → {config.TOPIC_TEMPERATURE}")
            else:
                print(f"[{DEVICE_ID}] ⚠️  Publish failed (code {result.rc})")

            # Wait before publishing the next reading
            time.sleep(config.TEMP_PUBLISH_INTERVAL)

    except KeyboardInterrupt:
        # Graceful shutdown on Ctrl+C
        print(f"\n[{DEVICE_ID}] 🛑 Shutting down...")
        client.loop_stop()
        client.disconnect()
        print(f"[{DEVICE_ID}] 👋 Disconnected cleanly.")


if __name__ == "__main__":
    main()
