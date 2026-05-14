# =============================================================================
# detection/anomaly_detector.py — Anomaly Detection Logic & Severity Scoring
# =============================================================================
# This module contains all the detection rules.
# It is called by monitor.py for every message received.
#
# Detection techniques used:
#   1. Rate-based detection    → counts messages per client per time window
#   2. Schema validation       → checks payload has expected fields/types
#   3. Value range checking    → flags impossible sensor values
#   4. Client ID authorisation → checks sender against whitelist
#   5. Wildcard subscription   → flags broad topic subscriptions
#
# Each detection function returns an Alert dict or None if nothing suspicious.
# =============================================================================

import json
import time
import sys
import os
from collections import defaultdict, deque

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


# ─────────────────────────────────────────────────────────────────────────────
# ALERT STRUCTURE
# Every alert is a Python dictionary with these standard fields.
# This makes it easy to log, display, and forward to Sentinel.
# ─────────────────────────────────────────────────────────────────────────────
def create_alert(alert_type, severity, description, details=None, client_id=None, topic=None):
    """
    Creates a standardised alert dictionary.

    alert_type  : Short category label (e.g., "DOS_FLOOD", "SPOOFING")
    severity    : LOW / MEDIUM / HIGH / CRITICAL
    description : Human-readable explanation of what was detected
    details     : Dict of extra context (optional)
    client_id   : The MQTT client that triggered the alert
    topic       : The MQTT topic involved
    """
    return {
        "alert_type":   alert_type,
        "severity":     severity,
        "description":  description,
        "client_id":    client_id or "unknown",
        "topic":        topic or "unknown",
        "timestamp":    time.time(),
        "details":      details or {}
    }


# =============================================================================
# CLASS: RateTracker
# Tracks how many messages each client sends in a sliding time window.
# Uses a deque (double-ended queue) per client for efficiency.
# =============================================================================
class RateTracker:
    def __init__(self, window_seconds=1):
        """
        window_seconds: how wide the sliding time window is (default: 1 second)
        We count messages within this window to calculate the rate.
        """
        self.window  = window_seconds
        # Each client gets a deque of timestamps for their recent messages
        self.records = defaultdict(deque)

    def record(self, client_id):
        """
        Record that client_id just sent a message.
        Returns the current message count for that client in the window.
        """
        now = time.time()
        dq  = self.records[client_id]

        # Add this message's timestamp
        dq.append(now)

        # Remove timestamps older than our window
        cutoff = now - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()

        return len(dq)  # Current count in the window

    def get_rate(self, client_id):
        """Returns current message rate for a client (messages/window)."""
        self.record.__doc__    # Touch to avoid unused warning
        return len(self.records[client_id])

    def get_all_rates(self):
        """Returns a dict of {client_id: rate} for all tracked clients."""
        now = time.time()
        rates = {}
        for client_id, dq in self.records.items():
            # Prune old entries first
            cutoff = now - self.window
            while dq and dq[0] < cutoff:
                dq.popleft()
            if dq:
                rates[client_id] = len(dq)
        return rates

    def get_total_rate(self):
        """Returns total messages/window across ALL clients."""
        return sum(self.get_all_rates().values())


# =============================================================================
# GLOBAL INSTANCES
# These persist across multiple calls to the detection functions,
# allowing us to track state over time.
# =============================================================================
rate_tracker        = RateTracker(window_seconds=1)
known_clients       = set()         # Track client IDs we've seen before
wildcard_subscribers = set()        # Track clients using '#' or '+' subscriptions


# =============================================================================
# DETECTION RULE 1: DoS / Message Flood Detection
# =============================================================================
def detect_dos(client_id, topic):
    """
    Detects unusually high message rates from a single client or overall.
    Returns an alert dict if threshold exceeded, else None.
    """
    # Record this message and get current rate
    client_rate = rate_tracker.record(client_id)
    total_rate  = rate_tracker.get_total_rate()

    # ── Per-client rate check ─────────────────────────────────────────────
    if client_rate > config.DOS_MSG_RATE_THRESHOLD:
        severity = (config.SEVERITY_CRITICAL
                    if client_rate > config.DOS_MSG_RATE_THRESHOLD * 3
                    else config.SEVERITY_HIGH)

        return create_alert(
            alert_type  = "DOS_FLOOD",
            severity    = severity,
            description = (f"Client '{client_id}' sending {client_rate} msgs/sec "
                           f"(threshold: {config.DOS_MSG_RATE_THRESHOLD})"),
            client_id   = client_id,
            topic       = topic,
            details     = {
                "client_rate":      client_rate,
                "total_rate":       total_rate,
                "threshold":        config.DOS_MSG_RATE_THRESHOLD,
                "recommendation":   "Implement broker-side rate limiting"
            }
        )

    # ── Total traffic rate check ──────────────────────────────────────────
    if total_rate > config.DOS_TOTAL_RATE_THRESHOLD:
        return create_alert(
            alert_type  = "DOS_TOTAL_FLOOD",
            severity    = config.SEVERITY_HIGH,
            description = (f"Total broker traffic: {total_rate} msgs/sec "
                           f"(threshold: {config.DOS_TOTAL_RATE_THRESHOLD})"),
            client_id   = client_id,
            topic       = topic,
            details     = {
                "total_rate": total_rate,
                "threshold":  config.DOS_TOTAL_RATE_THRESHOLD,
                "per_client_rates": rate_tracker.get_all_rates()
            }
        )

    return None     # No DoS detected


# =============================================================================
# DETECTION RULE 2: Unauthorised Client Detection
# =============================================================================
def detect_unauthorised_client(client_id, topic):
    """
    Flags any client_id not in the authorised devices list.
    This catches both spoofing attempts and rogue devices.
    """
    if client_id not in config.AUTHORISED_DEVICES:
        # Is it a known rogue (we've seen it before) or new?
        is_new = client_id not in known_clients
        known_clients.add(client_id)

        severity = config.SEVERITY_HIGH if is_new else config.SEVERITY_MEDIUM

        return create_alert(
            alert_type  = "UNAUTHORISED_CLIENT",
            severity    = severity,
            description = (f"{'NEW ' if is_new else ''}Unauthorised client "
                           f"'{client_id}' publishing on broker"),
            client_id   = client_id,
            topic       = topic,
            details     = {
                "is_new_client":    is_new,
                "authorised_list":  list(config.AUTHORISED_DEVICES),
                "recommendation":   "Enable MQTT authentication and ACLs"
            }
        )

    return None


# =============================================================================
# DETECTION RULE 3: Payload Schema Validation
# =============================================================================
def detect_schema_violation(client_id, topic, payload_str):
    """
    Validates that payloads conform to expected schemas.
    Spoofing attacks often use wrong field names or inject extra fields.
    """
    # ── Check payload size ────────────────────────────────────────────────
    if len(payload_str.encode("utf-8")) > config.MAX_PAYLOAD_BYTES:
        return create_alert(
            alert_type  = "OVERSIZED_PAYLOAD",
            severity    = config.SEVERITY_MEDIUM,
            description = (f"Payload size {len(payload_str)} bytes exceeds "
                           f"maximum {config.MAX_PAYLOAD_BYTES} bytes"),
            client_id   = client_id,
            topic       = topic,
            details     = {"payload_size": len(payload_str)}
        )

    # ── Parse JSON ────────────────────────────────────────────────────────
    try:
        payload = json.loads(payload_str)
    except json.JSONDecodeError:
        return create_alert(
            alert_type  = "INVALID_JSON",
            severity    = config.SEVERITY_MEDIUM,
            description = f"Non-JSON payload received on topic '{topic}'",
            client_id   = client_id,
            topic       = topic
        )

    # ── Topic-specific schema checks ─────────────────────────────────────
    if topic == config.TOPIC_TEMPERATURE:
        return _validate_temperature_payload(client_id, topic, payload)

    if topic == config.TOPIC_DOOR:
        return _validate_door_payload(client_id, topic, payload)

    return None


def _validate_temperature_payload(client_id, topic, payload):
    """Validates temperature sensor payload structure and value ranges."""

    # Required fields for a legitimate temperature reading
    required_fields = {"device_id", "device_type", "temperature", "timestamp"}
    missing = required_fields - set(payload.keys())

    if missing:
        return create_alert(
            alert_type  = "SCHEMA_VIOLATION",
            severity    = config.SEVERITY_MEDIUM,
            description = f"Temperature payload missing required fields: {missing}",
            client_id   = client_id,
            topic       = topic,
            details     = {
                "missing_fields":   list(missing),
                "received_fields":  list(payload.keys())
            }
        )

    # ── Value range check ─────────────────────────────────────────────────
    temp = payload.get("temperature")
    if temp is not None:
        if not isinstance(temp, (int, float)):
            return create_alert(
                alert_type  = "SCHEMA_VIOLATION",
                severity    = config.SEVERITY_MEDIUM,
                description = f"Temperature value is not numeric: {temp!r}",
                client_id   = client_id,
                topic       = topic
            )

        if not (config.TEMP_MIN_VALID <= temp <= config.TEMP_MAX_VALID):
            return create_alert(
                alert_type  = "OUT_OF_RANGE_VALUE",
                severity    = config.SEVERITY_HIGH,
                description = (f"Temperature {temp}°C is outside valid range "
                               f"[{config.TEMP_MIN_VALID}, {config.TEMP_MAX_VALID}]°C — "
                               f"possible spoofing or sensor fault"),
                client_id   = client_id,
                topic       = topic,
                details     = {
                    "received_value": temp,
                    "valid_min":      config.TEMP_MIN_VALID,
                    "valid_max":      config.TEMP_MAX_VALID
                }
            )

    # ── Suspicious extra fields check ─────────────────────────────────────
    suspicious_fields = {"cmd", "command", "exec", "shell", "script"}
    found_suspicious  = suspicious_fields & set(payload.keys())
    if found_suspicious:
        return create_alert(
            alert_type  = "INJECTION_ATTEMPT",
            severity    = config.SEVERITY_CRITICAL,
            description = (f"Suspicious command fields in payload: "
                           f"{found_suspicious}"),
            client_id   = client_id,
            topic       = topic,
            details     = {"suspicious_fields": list(found_suspicious)}
        )

    return None


def _validate_door_payload(client_id, topic, payload):
    """Validates door sensor payload."""
    valid_states = {"OPEN", "CLOSED"}
    state = payload.get("state")

    if state and state not in valid_states:
        return create_alert(
            alert_type  = "SCHEMA_VIOLATION",
            severity    = config.SEVERITY_MEDIUM,
            description = f"Invalid door state value: '{state}' (expected OPEN or CLOSED)",
            client_id   = client_id,
            topic       = topic,
            details     = {"received_state": state, "valid_states": list(valid_states)}
        )

    return None


# =============================================================================
# DETECTION RULE 4: Eavesdropping Detection
# =============================================================================
def detect_eavesdropping(client_id, subscribed_topic):
    """
    Called when a client subscribes to a topic.
    Wildcard subscriptions from unknown clients = eavesdropping.
    """
    is_wildcard = "#" in subscribed_topic or "+" in subscribed_topic
    is_authorised = client_id in config.AUTHORISED_WILDCARD_SUBSCRIBERS

    if is_wildcard and not is_authorised:
        # Track this client as a suspected eavesdropper
        wildcard_subscribers.add(client_id)

        return create_alert(
            alert_type  = "EAVESDROPPING",
            severity    = config.SEVERITY_MEDIUM,
            description = (f"Unauthorised wildcard subscription '{subscribed_topic}' "
                           f"by client '{client_id}' — possible eavesdropping"),
            client_id   = client_id,
            topic       = subscribed_topic,
            details     = {
                "wildcard_used":        subscribed_topic,
                "authorised_list":      list(config.AUTHORISED_WILDCARD_SUBSCRIBERS),
                "recommendation":       "Implement topic-level ACLs"
            }
        )

    return None


# =============================================================================
# MAIN ENTRY POINT: analyse_message
# Called by monitor.py for every incoming message.
# Runs all detection rules and returns a list of any triggered alerts.
# =============================================================================
def analyse_message(client_id, topic, payload_str):
    """
    Run all detection rules against an incoming message.
    Returns a list of Alert dicts (may be empty if nothing suspicious).
    """
    alerts = []

    # Run each detection rule in order
    # Each returns an alert dict, or None if no issue found

    alert = detect_dos(client_id, topic)
    if alert:
        alerts.append(alert)

    alert = detect_unauthorised_client(client_id, topic)
    if alert:
        alerts.append(alert)

    alert = detect_schema_violation(client_id, topic, payload_str)
    if alert:
        alerts.append(alert)

    return alerts
