# =============================================================================
# devices/motion_sensor.py — Simulated PIR Motion Sensor
# =============================================================================
# Simulates a Passive Infrared (PIR) motion sensor.
# These are widely used in smart homes and building automation.
# From a security perspective, motion data can reveal occupancy patterns —
# a valuable target for burglars or stalkers.
# =============================================================================

import paho.mqtt.client as mqtt
import json
import time
import random
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

DEVICE_ID   = "motion-sensor-01"
DEVICE_ROOM = "hallway"

motion_detected = False
last_motion_time = 0


def on_connect(client, userdata, flags, rc):
    status = "✅ Connected" if rc == 0 else f"❌ Failed (code {rc})"
    print(f"[{DEVICE_ID}] {status}")


def on_disconnect(client, userdata, rc):
    if rc != 0:
        print(f"[{DEVICE_ID}] ⚠️  Disconnected unexpectedly")


# ─────────────────────────────────────────────────────────────────────────────
# FUNCTION: simulate_motion
# Simulates realistic motion detection patterns.
# Motion is more likely during "active hours" and follows burst patterns.
# ─────────────────────────────────────────────────────────────────────────────
def simulate_motion():
    global motion_detected, last_motion_time

    current_time = time.time()
    seconds_since_last = current_time - last_motion_time

    if not motion_detected:
        # 20% chance of detecting motion each cycle
        if random.random() < 0.20:
            motion_detected = True
            last_motion_time = current_time
            return True, "DETECTED"
        return False, "CLEAR"
    else:
        # Motion resets after 30 seconds (typical PIR cool-down)
        if seconds_since_last > 30:
            motion_detected = False
            return False, "CLEAR"
        return True, "ACTIVE"   # Still within detection window


def build_payload(triggered, status):
    return json.dumps({
        "device_id":   DEVICE_ID,
        "device_type": "motion_sensor",
        "room":        DEVICE_ROOM,
        "triggered":   triggered,   # Boolean: True = motion detected
        "status":      status,      # "DETECTED", "ACTIVE", or "CLEAR"
        "sensitivity": "medium",    # Simulated sensitivity setting
        "timestamp":   time.time()
    })


def main():
    client = mqtt.Client(client_id=DEVICE_ID)
    client.on_connect    = on_connect
    client.on_disconnect = on_disconnect

    print(f"[{DEVICE_ID}] 🔌 Connecting to broker...")

    try:
        client.connect(config.BROKER_HOST, config.BROKER_PORT, config.BROKER_KEEPALIVE)
    except ConnectionRefusedError:
        print(f"[{DEVICE_ID}] ❌ Cannot connect. Is Mosquitto running?")
        sys.exit(1)

    client.loop_start()
    print(f"[{DEVICE_ID}] 👁️  Motion sensor active in [{DEVICE_ROOM}]")

    try:
        while True:
            triggered, status = simulate_motion()
            payload = build_payload(triggered, status)
            client.publish(config.TOPIC_MOTION, payload, qos=0)

            icon = "🔴" if triggered else "⚫"
            print(f"[{DEVICE_ID}] {icon} Motion: {status}")

            time.sleep(config.MOTION_PUBLISH_INTERVAL)

    except KeyboardInterrupt:
        print(f"\n[{DEVICE_ID}] 🛑 Shutting down...")
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()
