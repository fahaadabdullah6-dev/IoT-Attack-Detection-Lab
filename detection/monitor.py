# =============================================================================
# detection/monitor.py — Core MQTT Traffic Monitor & Alert Dispatcher
# =============================================================================
# This is the HEART of the detection system. It:
#   1. Connects to the MQTT broker and subscribes to ALL topics
#   2. Passes every message through the anomaly detection engine
#   3. Logs any triggered alerts to file
#   4. Optionally forwards alerts to Microsoft Sentinel
#   5. Maintains a shared alert queue that the dashboard reads from
#
# Architecture note:
#   The monitor subscribes to 'lab/#' (all lab topics) using a wildcard.
#   Every single message published by any device goes through our analysis.
#   This is known as "network tap" or "full packet inspection" in security.
# =============================================================================

import paho.mqtt.client as mqtt
import json
import time
import sys
import os
import threading
from datetime import datetime
from collections import deque

# ── Path setup ────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# ── Import our detection and alerting modules ─────────────────────────────────
from detection.anomaly_detector import analyse_message, detect_eavesdropping
from detection.sentinel_forwarder import forward_alert

# ─────────────────────────────────────────────────────────────────────────────
# SHARED STATE
# These variables are accessed by both monitor.py and terminal_dashboard.py.
# They act as a real-time "memory" of what the system has seen.
# ─────────────────────────────────────────────────────────────────────────────

# Thread-safe lock for shared state
state_lock = threading.Lock()

# Live device status: {device_id: {last_seen, message_count, last_value, topic}}
device_status = {}

# Recent alerts queue (newest alerts at the front)
# maxlen ensures we don't accumulate millions of alerts forever
alert_queue = deque(maxlen=1000)

# Statistics counters
stats = {
    "total_messages":   0,
    "total_alerts":     0,
    "start_time":       time.time(),
    "alerts_by_severity": {
        config.SEVERITY_LOW:      0,
        config.SEVERITY_MEDIUM:   0,
        config.SEVERITY_HIGH:     0,
        config.SEVERITY_CRITICAL: 0,
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# FUNCTION: log_alert
# Writes an alert to the log file AND the console.
# ─────────────────────────────────────────────────────────────────────────────

# Severity → emoji mapping for visual clarity
SEVERITY_ICONS = {
    config.SEVERITY_LOW:      "🔵",
    config.SEVERITY_MEDIUM:   "🟡",
    config.SEVERITY_HIGH:     "🔴",
    config.SEVERITY_CRITICAL: "💀",
}


def log_alert(alert):
    """
    Logs an alert to the alerts.log file and stdout.
    Also updates shared alert_queue and statistics counters.
    """
    with state_lock:
        # Add to in-memory queue (for dashboard)
        alert_queue.appendleft(alert)

        # Update statistics
        stats["total_alerts"] += 1
        severity = alert.get("severity", config.SEVERITY_LOW)
        if severity in stats["alerts_by_severity"]:
            stats["alerts_by_severity"][severity] += 1

    # ── Format for human-readable log ────────────────────────────────────
    timestamp   = datetime.fromtimestamp(alert["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
    icon        = SEVERITY_ICONS.get(severity, "⚪")
    log_line    = (f"[{timestamp}] {icon} [{severity:<8}] "
                   f"[{alert['alert_type']:<22}] "
                   f"Client: {alert['client_id']:<22} | "
                   f"{alert['description']}")

    # ── Write to log file ─────────────────────────────────────────────────
    log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "alerts.log")

    try:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(log_line + "\n")
            # Also write the full JSON for machine-readable processing
            f.write("  JSON: " + json.dumps(alert) + "\n")
    except IOError as e:
        print(f"[Monitor] ⚠️  Could not write to log file: {e}")

    # ── Print to console ──────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print(f"  🚨 ALERT DETECTED")
    print(f"{'='*70}")
    print(f"  {log_line}")
    if alert.get("details"):
        print(f"  Details: {json.dumps(alert['details'], indent=4)[:200]}")
    print(f"{'='*70}\n")

    # ── Forward to Sentinel (if enabled) ─────────────────────────────────
    if config.SENTINEL_ENABLED:
        forward_alert(alert)


# ─────────────────────────────────────────────────────────────────────────────
# FUNCTION: update_device_status
# Maintains our live view of each device's current state.
# Called for every message — keeps the dashboard data fresh.
# ─────────────────────────────────────────────────────────────────────────────
def update_device_status(client_id, topic, payload_str):
    """Update the live device registry with the latest message info."""
    try:
        payload = json.loads(payload_str)
    except (json.JSONDecodeError, TypeError):
        payload = {}

    # Extract the most relevant "last value" to display per device type
    if "temperature" in payload:
        last_value = f"{payload['temperature']}°C"
    elif "state" in payload:
        last_value = payload["state"]
    elif "power" in payload:
        last_value = f"{payload['power']} @ {payload.get('brightness', 0)}%"
    elif "status" in payload:
        last_value = payload["status"]
    else:
        last_value = "data received"

    with state_lock:
        if client_id not in device_status:
            # First time seeing this device
            device_status[client_id] = {
                "client_id":     client_id,
                "topic":         topic,
                "message_count": 0,
                "last_seen":     time.time(),
                "last_value":    last_value,
                "status":        "active",
                "first_seen":    time.time()
            }
        else:
            # Update existing device record
            device_status[client_id]["last_seen"]     = time.time()
            device_status[client_id]["last_value"]    = last_value
            device_status[client_id]["message_count"] += 1
            device_status[client_id]["topic"]         = topic
            device_status[client_id]["status"]        = "active"


# ─────────────────────────────────────────────────────────────────────────────
# FUNCTION: mark_stale_devices
# Periodically checks for devices that haven't published recently.
# A suddenly-silent device could indicate it's been taken offline by an attack.
# ─────────────────────────────────────────────────────────────────────────────
def mark_stale_devices():
    """Background thread: marks devices as 'stale' if silent for too long."""
    STALE_THRESHOLD = 60    # 60 seconds without a message = stale

    while True:
        time.sleep(10)      # Check every 10 seconds
        now = time.time()

        with state_lock:
            for device_id, info in device_status.items():
                seconds_silent = now - info["last_seen"]
                if seconds_silent > STALE_THRESHOLD:
                    device_status[device_id]["status"] = "stale"
                else:
                    device_status[device_id]["status"] = "active"


# ─────────────────────────────────────────────────────────────────────────────
# MQTT CALLBACKS
# ─────────────────────────────────────────────────────────────────────────────

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"[Monitor] ✅ Detection engine connected to broker "
              f"{config.BROKER_HOST}:{config.BROKER_PORT}")

        # Subscribe to ALL lab topics — this is how we see every message
        client.subscribe(config.TOPIC_WILDCARD, qos=0)
        print(f"[Monitor] 👁️  Subscribed to: {config.TOPIC_WILDCARD}")
        print("[Monitor] 🔍 Anomaly detection ACTIVE\n")
    else:
        print(f"[Monitor] ❌ Connection failed (code {rc})")
        print("[Monitor]    Ensure Mosquitto broker is running first.")


def on_disconnect(client, userdata, rc):
    if rc != 0:
        print(f"[Monitor] ⚠️  Unexpected disconnect (code {rc})")
        print("[Monitor] 🔄 Paho will attempt automatic reconnect...")


def on_message(client, userdata, msg):
    """
    Called for EVERY message received on the broker.
    This is the main analysis pipeline entry point.
    """
    # Decode bytes → string
    try:
        payload_str = msg.payload.decode("utf-8")
    except UnicodeDecodeError:
        payload_str = msg.payload.decode("utf-8", errors="replace")

    # Extract client ID from payload (MQTT doesn't expose sender ID in callbacks
    # without additional broker support — so we read it from the payload itself)
    try:
        payload_obj = json.loads(payload_str)
        client_id   = payload_obj.get("device_id", "unknown")
    except (json.JSONDecodeError, AttributeError):
        client_id   = "unknown"
        payload_obj = {}

    topic = msg.topic

    # ── Update statistics ─────────────────────────────────────────────────
    with state_lock:
        stats["total_messages"] += 1

    # ── Update live device registry ───────────────────────────────────────
    update_device_status(client_id, topic, payload_str)

    # ── Run anomaly detection ─────────────────────────────────────────────
    # analyse_message returns a list of alerts (usually empty for normal traffic)
    alerts = analyse_message(client_id, topic, payload_str)

    # ── Process each alert ────────────────────────────────────────────────
    for alert in alerts:
        log_alert(alert)


def on_subscribe(client, userdata, mid, granted_qos):
    """Called when a subscription is acknowledged by the broker."""
    print(f"[Monitor] ✅ Subscription confirmed (QoS: {granted_qos})")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print("\n" + "=" * 65)
    print("  🛡️  IoT ATTACK DETECTION LAB — Security Monitor")
    print("=" * 65)
    print(f"  Broker      : {config.BROKER_HOST}:{config.BROKER_PORT}")
    print(f"  Monitoring  : {config.TOPIC_WILDCARD}")
    print(f"  Log File    : {config.LOG_FILE_PATH}")
    print(f"  Sentinel    : {'ENABLED' if config.SENTINEL_ENABLED else 'DISABLED'}")
    print(f"  DoS Thresh  : {config.DOS_MSG_RATE_THRESHOLD} msgs/sec")
    print("=" * 65 + "\n")

    # ── Ensure log directory exists ───────────────────────────────────────
    log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
    os.makedirs(log_dir, exist_ok=True)

    # Write session start marker to log
    log_file = os.path.join(log_dir, "alerts.log")
    with open(log_file, "a") as f:
        f.write(f"\n{'='*70}\n")
        f.write(f"  DETECTION SESSION STARTED: "
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"{'='*70}\n")

    # ── Start background stale-device checker ─────────────────────────────
    stale_checker = threading.Thread(
        target=mark_stale_devices,
        daemon=True,
        name="StaleDeviceChecker"
    )
    stale_checker.start()

    # ── Set up MQTT client ─────────────────────────────────────────────────
    client = mqtt.Client(client_id="detection-engine")
    client.on_connect   = on_connect
    client.on_disconnect = on_disconnect
    client.on_message   = on_message
    client.on_subscribe = on_subscribe

    try:
        client.connect(config.BROKER_HOST, config.BROKER_PORT, config.BROKER_KEEPALIVE)
    except ConnectionRefusedError:
        print("[Monitor] ❌ Cannot connect to broker.")
        print("[Monitor]    Start Mosquitto: sudo systemctl start mosquitto")
        sys.exit(1)

    print("[Monitor] 🚀 Detection engine running. Waiting for messages...")
    print("[Monitor]    Start devices: python devices/device_runner.py")
    print("[Monitor]    Run attacks:   python attacks/dos_flood.py")
    print("[Monitor]    Press Ctrl+C to stop.\n")

    try:
        # loop_forever() handles reconnections automatically
        client.loop_forever()

    except KeyboardInterrupt:
        print("\n[Monitor] 🛑 Shutting down detection engine...")
        client.disconnect()

        # Print final session statistics
        elapsed = time.time() - stats["start_time"]
        print(f"\n{'='*50}")
        print("  📊 SESSION STATISTICS")
        print(f"{'='*50}")
        print(f"  Duration        : {elapsed:.0f} seconds")
        print(f"  Total Messages  : {stats['total_messages']}")
        print(f"  Total Alerts    : {stats['total_alerts']}")
        for sev, count in stats["alerts_by_severity"].items():
            icon = SEVERITY_ICONS.get(sev, "⚪")
            print(f"  {icon} {sev:<10}: {count}")
        print(f"{'='*50}\n")


if __name__ == "__main__":
    main()
