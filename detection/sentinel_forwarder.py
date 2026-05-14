# =============================================================================
# detection/sentinel_forwarder.py — Forward Alerts to Microsoft Sentinel
# =============================================================================
# This module sends security alerts to Azure Log Analytics (the data backend
# for Microsoft Sentinel) using the HTTP Data Collector API.
#
# How it works:
#   1. Build a JSON payload containing the alert details
#   2. Create an HMAC-SHA256 signature using the workspace key
#   3. POST to the Log Analytics REST API endpoint
#   4. Sentinel ingests it as a custom log table
#
# Setup required:
#   - Azure account + Log Analytics Workspace
#   - Set SENTINEL_WORKSPACE_ID and SENTINEL_PRIMARY_KEY in config.py
#   - Set SENTINEL_ENABLED = True in config.py
#
# The custom table will appear in Sentinel as: IoTAttackDetectionLab_CL
# =============================================================================

import json
import time
import hmac
import hashlib
import base64
import requests
import sys
import os
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


# ─────────────────────────────────────────────────────────────────────────────
# FUNCTION: build_signature
# Creates the HMAC-SHA256 authentication signature required by Azure.
# Azure uses this to verify the request is from an authorised source.
#
# The signature format is defined by Microsoft's Log Analytics API spec:
# https://docs.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api
# ─────────────────────────────────────────────────────────────────────────────
def build_signature(workspace_id, primary_key, date_string, content_length, method,
                    content_type, resource):
    """
    Builds the Authorization header value for the Log Analytics API.

    workspace_id    : Your Azure Log Analytics Workspace ID
    primary_key     : Workspace primary or secondary key (base64 encoded)
    date_string     : RFC 1123 formatted date (e.g., "Mon, 01 Jan 2024 12:00:00 GMT")
    content_length  : Length of the JSON body in bytes
    method          : HTTP method (always "POST" here)
    content_type    : MIME type (always "application/json")
    resource        : API endpoint path (always "/api/logs")
    """
    # Build the string-to-sign per Azure spec
    x_headers   = f"x-ms-date:{date_string}"
    string_to_sign = (f"{method}\n"
                      f"{content_length}\n"
                      f"{content_type}\n"
                      f"{x_headers}\n"
                      f"{resource}")

    # Decode the workspace key from base64 (Azure stores it base64-encoded)
    decoded_key = base64.b64decode(primary_key)

    # Create HMAC-SHA256 signature
    signature = base64.b64encode(
        hmac.new(decoded_key, string_to_sign.encode("utf-8"), digestmod=hashlib.sha256).digest()
    ).decode("utf-8")

    # Return the full Authorization header value
    return f"SharedKey {workspace_id}:{signature}"


# ─────────────────────────────────────────────────────────────────────────────
# FUNCTION: forward_alert
# Sends a single alert dict to Microsoft Sentinel via Log Analytics API.
# Returns True on success, False on failure.
# ─────────────────────────────────────────────────────────────────────────────
def forward_alert(alert):
    """
    Forward one alert dict to Azure Sentinel.
    The 'alert' dict comes from anomaly_detector.create_alert().
    """

    # ── Check if Sentinel is configured ──────────────────────────────────
    if not config.SENTINEL_ENABLED:
        return False    # Silently skip if not enabled

    if not config.SENTINEL_WORKSPACE_ID or not config.SENTINEL_PRIMARY_KEY:
        print("[Sentinel] ⚠️  Workspace ID or Key not configured. Skipping.")
        return False

    # ── Prepare the payload ───────────────────────────────────────────────
    # Convert Unix timestamp to ISO 8601 format that Azure expects
    alert_time = datetime.fromtimestamp(
        alert.get("timestamp", time.time()), tz=timezone.utc
    ).isoformat()

    # Build the log entry — add any extra fields Sentinel analysts would need
    log_entry = {
        "TimeGenerated":    alert_time,         # Azure standard field
        "AlertType":        alert["alert_type"],
        "Severity":         alert["severity"],
        "Description":      alert["description"],
        "ClientId":         alert["client_id"],
        "Topic":            alert["topic"],
        "Details":          json.dumps(alert.get("details", {})),   # Nested as string
        "LabName":          "IoT-Attack-Detection-Lab",
        "DetectionEngine":  "Python-MQTT-Monitor-v1.0"
    }

    # JSON-encode the log entry (Azure expects an array of objects)
    body = json.dumps([log_entry])
    body_bytes = body.encode("utf-8")

    # ── Build HTTP headers ────────────────────────────────────────────────
    # RFC 1123 date format required by Azure API
    date_string = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")

    signature = build_signature(
        workspace_id   = config.SENTINEL_WORKSPACE_ID,
        primary_key    = config.SENTINEL_PRIMARY_KEY,
        date_string    = date_string,
        content_length = len(body_bytes),
        method         = "POST",
        content_type   = "application/json",
        resource       = "/api/logs"
    )

    headers = {
        "Content-Type":  "application/json",
        "Authorization": signature,
        "Log-Type":      config.SENTINEL_LOG_TYPE,  # Custom table name
        "x-ms-date":     date_string,
        "time-generated-field": "TimeGenerated"
    }

    # ── Send to Azure API ─────────────────────────────────────────────────
    url = (f"https://{config.SENTINEL_WORKSPACE_ID}"
           f".ods.opinsights.azure.com/api/logs?api-version=2016-04-01")

    try:
        response = requests.post(url, data=body_bytes, headers=headers, timeout=10)

        if response.status_code == 200:
            print(f"[Sentinel] ✅ Alert forwarded: {alert['alert_type']} "
                  f"({alert['severity']})")
            return True
        else:
            print(f"[Sentinel] ❌ API error {response.status_code}: {response.text[:100]}")
            return False

    except requests.exceptions.ConnectionError:
        print("[Sentinel] ❌ Network error — check internet connection")
        return False
    except requests.exceptions.Timeout:
        print("[Sentinel] ❌ Request timed out")
        return False
    except Exception as e:
        print(f"[Sentinel] ❌ Unexpected error: {e}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# FUNCTION: test_connection
# Sends a test event to verify Sentinel connectivity is working.
# Call this manually to confirm your credentials are correct.
# ─────────────────────────────────────────────────────────────────────────────
def test_connection():
    """Send a test alert to verify Sentinel connectivity."""
    test_alert = {
        "alert_type":   "CONNECTION_TEST",
        "severity":     "LOW",
        "description":  "Test alert from IoT Attack Detection Lab",
        "client_id":    "test-client",
        "topic":        "test/topic",
        "timestamp":    time.time(),
        "details":      {"message": "If you see this in Sentinel, the connection works!"}
    }
    print("[Sentinel] 🔗 Testing connection...")
    result = forward_alert(test_alert)
    if result:
        print("[Sentinel] ✅ Test successful! Check your Sentinel workspace.")
        print(f"           Table: {config.SENTINEL_LOG_TYPE}_CL")
    else:
        print("[Sentinel] ❌ Test failed. Check workspace ID and key in config.py")


# ── Quick test if run directly ────────────────────────────────────────────────
if __name__ == "__main__":
    print("Testing Microsoft Sentinel connection...")
    test_connection()
