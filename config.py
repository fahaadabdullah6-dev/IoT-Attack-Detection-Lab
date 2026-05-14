# =============================================================================
# config.py — Central Configuration for IoT Attack Detection Lab
# =============================================================================
# All scripts import from this file so you only need to change settings here.
# This is good practice — avoids "magic numbers" scattered across many files.
# =============================================================================

# ── MQTT BROKER SETTINGS ─────────────────────────────────────────────────────
# The broker is the central hub that all devices and monitors connect to.
# Default Mosquitto runs on localhost (127.0.0.1) port 1883.

BROKER_HOST = "localhost"       # Change to broker's IP if running remotely
BROKER_PORT = 1883              # Default unencrypted MQTT port
BROKER_KEEPALIVE = 60           # Seconds between keepalive pings to broker

# ── MQTT TOPIC STRUCTURE ─────────────────────────────────────────────────────
# Topics are like "channels". Devices publish to specific topics.
# We use a hierarchy: lab/<device_type>/<device_id>

TOPIC_BASE        = "lab"
TOPIC_TEMPERATURE = "lab/sensors/temperature"
TOPIC_DOOR        = "lab/sensors/door"
TOPIC_MOTION      = "lab/sensors/motion"
TOPIC_LIGHT       = "lab/devices/light"
TOPIC_WILDCARD    = "lab/#"     # Subscribes to ALL topics under "lab/"

# ── AUTHORISED DEVICE REGISTRY ───────────────────────────────────────────────
# These are the KNOWN, LEGITIMATE device client IDs.
# Any device NOT in this list connecting to the broker will trigger an alert.

AUTHORISED_DEVICES = {
    "temp-sensor-01",
    "temp-sensor-02",
    "door-sensor-01",
    "motion-sensor-01",
    "smart-light-01",
    "detection-engine",     # The monitor itself
    "dashboard-client",     # The dashboard subscriber
}

# ── AUTHORISED SUBSCRIBERS ───────────────────────────────────────────────────
# Client IDs that are ALLOWED to use wildcard subscriptions.
# Anyone else using "#" or "+" wildcards is flagged as potential eavesdropping.

AUTHORISED_WILDCARD_SUBSCRIBERS = {
    "detection-engine",
    "dashboard-client",
}

# ── DETECTION THRESHOLDS ─────────────────────────────────────────────────────
# These thresholds control when the detection engine raises alerts.
# Tune these based on your expected "normal" traffic volume.

# DoS Detection: max messages a single client can send in one second
DOS_MSG_RATE_THRESHOLD = 20     # More than 20 msgs/sec = suspicious

# DoS Detection: max total messages across ALL clients per second
DOS_TOTAL_RATE_THRESHOLD = 100  # More than 100 msgs/sec total = suspicious

# Payload size: max expected bytes for a normal sensor reading
MAX_PAYLOAD_BYTES = 512         # Payloads larger than this are flagged

# Temperature sensor: valid range in Celsius
TEMP_MIN_VALID = -20.0
TEMP_MAX_VALID = 85.0

# ── DEVICE SIMULATION SETTINGS ───────────────────────────────────────────────
# How often each simulated device publishes a reading (seconds)

TEMP_PUBLISH_INTERVAL   = 5     # Temperature sensor publishes every 5 sec
DOOR_PUBLISH_INTERVAL   = 10    # Door sensor publishes every 10 sec
MOTION_PUBLISH_INTERVAL = 7     # Motion sensor publishes every 7 sec
LIGHT_PUBLISH_INTERVAL  = 8     # Smart light publishes every 8 sec

# ── ALERT SEVERITY LEVELS ────────────────────────────────────────────────────
# Used consistently across detection engine, logger, and dashboard

SEVERITY_LOW    = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH   = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

# ── LOGGING SETTINGS ─────────────────────────────────────────────────────────
LOG_FILE_PATH = "logs/alerts.log"   # Relative path from project root

# ── MICROSOFT SENTINEL (OPTIONAL) ────────────────────────────────────────────
# Leave these blank ("") to disable Sentinel forwarding.
# Fill them in from your Azure Log Analytics Workspace settings.

SENTINEL_ENABLED      = False       # Set to True to enable forwarding
SENTINEL_WORKSPACE_ID = ""          # Azure Log Analytics Workspace ID
SENTINEL_PRIMARY_KEY  = ""          # Primary or Secondary Key from Azure portal
SENTINEL_LOG_TYPE     = "IoTAttackDetectionLab"  # Custom log table name in Sentinel

# ── DASHBOARD SETTINGS ────────────────────────────────────────────────────────
DASHBOARD_REFRESH_RATE = 1.0        # How often (seconds) the dashboard redraws
MAX_ALERTS_DISPLAYED   = 15         # Number of recent alerts shown on dashboard
