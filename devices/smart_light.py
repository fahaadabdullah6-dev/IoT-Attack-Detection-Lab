# =============================================================================
# devices/smart_light.py — Simulated Smart Light Bulb
# =============================================================================
# Simulates a smart bulb (like Philips Hue or IKEA TRÅDFRI).
# Publishes its current on/off state and brightness level.
#
# In real attacks, smart lights have been used as a side channel:
# rapidly flashing them can encode data (optical exfiltration), or
# attackers can control them to cause distress / social engineering.
# =============================================================================

import paho.mqtt.client as mqtt
import json
import time
import random
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

DEVICE_ID    = "smart-light-01"
DEVICE_ROOM  = "kitchen"

# Current light state
light_on   = True
brightness = 80     # 0–100 percentage


def on_connect(client, userdata, flags, rc):
    status = "✅ Connected" if rc == 0 else f"❌ Failed (code {rc})"
    print(f"[{DEVICE_ID}] {status}")


def on_disconnect(client, userdata, rc):
    if rc != 0:
        print(f"[{DEVICE_ID}] ⚠️  Disconnected unexpectedly")


# ─────────────────────────────────────────────────────────────────────────────
# FUNCTION: simulate_light_state
# Randomly varies the light's state to simulate user interactions.
# ─────────────────────────────────────────────────────────────────────────────
def simulate_light_state():
    global light_on, brightness

    # 10% chance of toggling on/off each cycle
    if random.random() < 0.10:
        light_on = not light_on

    if light_on:
        # Brightness drifts slightly each cycle (simulates dimmer adjustments)
        delta = random.randint(-5, 5)
        brightness = max(10, min(100, brightness + delta))

    return light_on, brightness


def build_payload(is_on, bright_level):
    return json.dumps({
        "device_id":   DEVICE_ID,
        "device_type": "smart_light",
        "room":        DEVICE_ROOM,
        "power":       "ON" if is_on else "OFF",
        "brightness":  bright_level if is_on else 0,
        "color_temp":  2700,    # Warm white in Kelvin (static for this sim)
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
    print(f"[{DEVICE_ID}] 💡 Smart light simulation running in [{DEVICE_ROOM}]")

    try:
        while True:
            is_on, bright_level = simulate_light_state()
            payload = build_payload(is_on, bright_level)
            client.publish(config.TOPIC_LIGHT, payload, qos=0)

            icon = "💡" if is_on else "⬛"
            bright_str = f"@ {bright_level}%" if is_on else "(off)"
            print(f"[{DEVICE_ID}] {icon} Light: {'ON' if is_on else 'OFF'} {bright_str}")

            time.sleep(config.LIGHT_PUBLISH_INTERVAL)

    except KeyboardInterrupt:
        print(f"\n[{DEVICE_ID}] 🛑 Shutting down...")
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()
