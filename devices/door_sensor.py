# =============================================================================
# devices/door_sensor.py — Simulated Door/Window Sensor
# =============================================================================
# Simulates a magnetic contact sensor (like those on alarm systems).
# Publishes OPEN/CLOSED state changes to the MQTT broker.
#
# Real-world equivalent: Xiaomi door sensor, Z-Wave contact sensor
# These are common targets in smart home attacks — knowing when a door
# is open/closed can reveal occupancy patterns.
# =============================================================================

import paho.mqtt.client as mqtt
import json
import time
import random
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

DEVICE_ID       = "door-sensor-01"
DEVICE_LOCATION = "front_door"

# Track current door state (starts closed)
door_state = "CLOSED"
open_duration = 0   # How many cycles the door has been open


def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"[{DEVICE_ID}] ✅ Connected to MQTT broker")
    else:
        print(f"[{DEVICE_ID}] ❌ Connection failed (code {rc})")


def on_disconnect(client, userdata, rc):
    if rc != 0:
        print(f"[{DEVICE_ID}] ⚠️  Unexpected disconnection")


# ─────────────────────────────────────────────────────────────────────────────
# FUNCTION: simulate_door_event
# Randomly toggles door state to mimic real usage patterns.
# Doors are usually closed; they open briefly and close again.
# ─────────────────────────────────────────────────────────────────────────────
def simulate_door_event():
    global door_state, open_duration

    if door_state == "CLOSED":
        # 15% chance the door opens each cycle
        if random.random() < 0.15:
            door_state = "OPEN"
            open_duration = 0
            return door_state, True    # (state, changed)
    else:
        # Door is open — increment duration counter
        open_duration += 1
        # 60% chance it closes each cycle, or force-close after 3 cycles
        if random.random() < 0.60 or open_duration >= 3:
            door_state = "CLOSED"
            open_duration = 0
            return door_state, True

    return door_state, False    # No state change


def build_payload(state, changed):
    return json.dumps({
        "device_id":   DEVICE_ID,
        "device_type": "door_sensor",
        "location":    DEVICE_LOCATION,
        "state":       state,           # "OPEN" or "CLOSED"
        "changed":     changed,         # True if this is a state change event
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
        print(f"[{DEVICE_ID}] ❌ Broker not reachable. Start Mosquitto first.")
        sys.exit(1)

    client.loop_start()

    print(f"[{DEVICE_ID}] 🚪 Starting door sensor simulation...")

    try:
        while True:
            state, changed = simulate_door_event()
            payload = build_payload(state, changed)

            # Use QoS 1 for door events — we don't want to miss them
            result = client.publish(config.TOPIC_DOOR, payload, qos=1)

            # Show a visual indicator of door state
            icon = "🔓" if state == "OPEN" else "🔒"
            change_indicator = " ← STATE CHANGE!" if changed else ""
            print(f"[{DEVICE_ID}] {icon} Door: {state}{change_indicator}")

            time.sleep(config.DOOR_PUBLISH_INTERVAL)

    except KeyboardInterrupt:
        print(f"\n[{DEVICE_ID}] 🛑 Shutting down...")
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()
