# =============================================================================
# dashboard/terminal_dashboard.py — Live Terminal Security Dashboard
# =============================================================================
# A real-time, colour-coded terminal UI showing:
#   • Live IoT device status (last value, message count, health)
#   • Recent security alerts (with severity colour-coding)
#   • Traffic statistics (message rates, alert counts)
#
# Built with the 'rich' library which provides beautiful terminal output:
#   https://github.com/Textualize/rich
#
# The dashboard reads from the shared state maintained by monitor.py.
# It must be run in a SEPARATE terminal AFTER monitor.py is running.
#
# HOW IT WORKS:
#   1. This script imports the shared state (device_status, alert_queue)
#      from monitor.py's module
#   2. It subscribes to MQTT too, but ONLY to update the shared state
#      (alternatively, monitor.py can be imported as a module)
#   3. Rich's Live context manager redraws the screen every second
# =============================================================================

import sys
import os
import time
import json
import threading
from datetime import datetime
from collections import deque

# ── Rich imports — for beautiful terminal UI ──────────────────────────────────
from rich.console import Console
from rich.table   import Table
from rich.panel   import Panel
from rich.layout  import Layout
from rich.live    import Live
from rich.text    import Text
from rich.columns import Columns
from rich import box

import paho.mqtt.client as mqtt

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# ─────────────────────────────────────────────────────────────────────────────
# STANDALONE SHARED STATE
# The dashboard maintains its own state by subscribing to MQTT independently.
# This means it works even if monitor.py is run separately.
# ─────────────────────────────────────────────────────────────────────────────

# Lock for thread-safe state access
lock = threading.Lock()

# Device registry: {device_id: {...}}
devices = {}

# Recent alerts: newest first
alerts = deque(maxlen=config.MAX_ALERTS_DISPLAYED)

# Traffic counters
counters = {
    "total_messages":     0,
    "messages_last_min":  deque(maxlen=60),   # Per-second counts for last 60s
    "alerts_by_severity": {
        config.SEVERITY_LOW:      0,
        config.SEVERITY_MEDIUM:   0,
        config.SEVERITY_HIGH:     0,
        config.SEVERITY_CRITICAL: 0,
    },
    "start_time": time.time()
}

# ─────────────────────────────────────────────────────────────────────────────
# SEVERITY COLOUR MAPPING
# Maps alert severity to Rich colour names for visual distinction
# ─────────────────────────────────────────────────────────────────────────────
SEVERITY_COLORS = {
    config.SEVERITY_LOW:      "bright_blue",
    config.SEVERITY_MEDIUM:   "yellow",
    config.SEVERITY_HIGH:     "red",
    config.SEVERITY_CRITICAL: "bold red on white",
}

SEVERITY_ICONS = {
    config.SEVERITY_LOW:      "🔵",
    config.SEVERITY_MEDIUM:   "🟡",
    config.SEVERITY_HIGH:     "🔴",
    config.SEVERITY_CRITICAL: "💀",
}


# ─────────────────────────────────────────────────────────────────────────────
# MQTT SETUP — Dashboard's own subscriber connection
# ─────────────────────────────────────────────────────────────────────────────

def on_connect_dashboard(client, userdata, flags, rc):
    if rc == 0:
        # Subscribe to ALL device topics AND the alert log
        client.subscribe(config.TOPIC_WILDCARD, qos=0)
    else:
        pass    # Silently fail — dashboard shows "disconnected" state


def on_message_dashboard(client, userdata, msg):
    """Update device state when we receive any MQTT message."""
    try:
        payload_str = msg.payload.decode("utf-8")
        payload     = json.loads(payload_str)
        device_id   = payload.get("device_id", "unknown")
    except Exception:
        return

    # Extract display value
    if "temperature" in payload:
        value = f"{payload['temperature']}°C"
        dtype = "🌡️  Temp Sensor"
    elif "state" in payload:
        state = payload["state"]
        value = f"{'🔓' if state == 'OPEN' else '🔒'} {state}"
        dtype = "🚪 Door Sensor"
    elif "triggered" in payload:
        val   = payload.get("status", "UNKNOWN")
        value = f"{'🔴' if payload['triggered'] else '⚫'} {val}"
        dtype = "👁️  Motion Sensor"
    elif "power" in payload:
        pwr   = payload["power"]
        bri   = payload.get("brightness", 0)
        value = f"{'💡' if pwr == 'ON' else '⬛'} {pwr} @ {bri}%"
        dtype = "💡 Smart Light"
    else:
        value = "data"
        dtype = "📡 Device"

    with lock:
        counters["total_messages"] += 1

        if device_id not in devices:
            devices[device_id] = {
                "type":          dtype,
                "topic":         msg.topic,
                "message_count": 0,
                "last_seen":     time.time(),
                "last_value":    value,
                "first_seen":    time.time()
            }
        else:
            devices[device_id].update({
                "last_seen":     time.time(),
                "last_value":    value,
                "message_count": devices[device_id]["message_count"] + 1,
                "type":          dtype,
                "topic":         msg.topic
            })


# ─────────────────────────────────────────────────────────────────────────────
# ALERT READER — Reads alerts from the log file and adds to our deque
# ─────────────────────────────────────────────────────────────────────────────

def tail_alerts_log():
    """
    Background thread: continuously reads new alerts from logs/alerts.log.
    Uses a "tail -f" style approach — tracks file position to read only new lines.
    """
    log_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "logs", "alerts.log"
    )

    last_position = 0

    while True:
        try:
            if os.path.exists(log_path):
                with open(log_path, "r", encoding="utf-8") as f:
                    # Seek to where we left off
                    f.seek(last_position)
                    lines = f.readlines()
                    last_position = f.tell()

                # Parse JSON lines (those starting with "  JSON:")
                for line in lines:
                    if line.strip().startswith("JSON:"):
                        try:
                            json_str = line.strip()[5:].strip()
                            alert    = json.loads(json_str)
                            with lock:
                                alerts.appendleft(alert)
                                sev = alert.get("severity", config.SEVERITY_LOW)
                                if sev in counters["alerts_by_severity"]:
                                    counters["alerts_by_severity"][sev] += 1
                        except json.JSONDecodeError:
                            pass

        except IOError:
            pass    # Log file might not exist yet

        time.sleep(0.5)     # Check for new alerts every 0.5 seconds


# ─────────────────────────────────────────────────────────────────────────────
# DASHBOARD RENDERING FUNCTIONS
# Each function builds a Rich renderable (Table, Panel, etc.)
# ─────────────────────────────────────────────────────────────────────────────

def build_header():
    """Top header with title and current time."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    elapsed = int(time.time() - counters["start_time"])
    h, m, s = elapsed // 3600, (elapsed % 3600) // 60, elapsed % 60

    title = Text()
    title.append("🛡️  IoT ATTACK DETECTION LAB", style="bold white on dark_blue")
    title.append(f"  |  {now}", style="dim white")
    title.append(f"  |  Uptime: {h:02d}:{m:02d}:{s:02d}", style="dim cyan")

    return Panel(title, box=box.DOUBLE_EDGE, style="blue")


def build_device_table():
    """Table showing live status of all known IoT devices."""
    table = Table(
        title="📡 Live Device Status",
        box=box.ROUNDED,
        style="blue",
        header_style="bold cyan",
        show_lines=True
    )

    table.add_column("Device ID",     style="cyan",  width=22)
    table.add_column("Type",          style="white", width=16)
    table.add_column("Last Value",    style="green", width=22)
    table.add_column("Messages",      style="white", justify="right", width=8)
    table.add_column("Last Seen",     style="dim",   width=10)
    table.add_column("Status",        style="white", width=10)

    with lock:
        device_snapshot = dict(devices)

    if not device_snapshot:
        table.add_row(
            "[dim]Waiting for devices...[/dim]",
            "", "", "", "", ""
        )
        return table

    for device_id, info in sorted(device_snapshot.items()):
        # Determine device health based on last-seen time
        seconds_ago = time.time() - info["last_seen"]

        if seconds_ago < 30:
            status_text = Text("● ACTIVE",  style="bold green")
        elif seconds_ago < 120:
            status_text = Text("● SLOW",    style="bold yellow")
        else:
            status_text = Text("○ OFFLINE", style="dim red")

        # Format last-seen as "N sec ago" or "Nm Ns ago"
        if seconds_ago < 60:
            seen_str = f"{seconds_ago:.0f}s ago"
        else:
            seen_str = f"{seconds_ago/60:.1f}m ago"

        # Highlight unauthorised devices in red
        id_style = "bold red" if device_id not in config.AUTHORISED_DEVICES else "cyan"

        table.add_row(
            Text(device_id,             style=id_style),
            info.get("type", "Unknown"),
            info.get("last_value", "-"),
            str(info.get("message_count", 0)),
            seen_str,
            status_text
        )

    return table


def build_alerts_table():
    """Table of recent security alerts with colour-coded severity."""
    table = Table(
        title=f"🚨 Recent Alerts (last {config.MAX_ALERTS_DISPLAYED})",
        box=box.ROUNDED,
        style="red",
        header_style="bold red",
        show_lines=True
    )

    table.add_column("Time",        style="dim",   width=10)
    table.add_column("Severity",    style="white", width=10)
    table.add_column("Type",        style="white", width=22)
    table.add_column("Client",      style="cyan",  width=22)
    table.add_column("Description", style="white", width=45)

    with lock:
        alert_snapshot = list(alerts)

    if not alert_snapshot:
        table.add_row(
            "", "",
            "[dim]No alerts yet — system is clean[/dim]",
            "", ""
        )
        return table

    for alert in alert_snapshot[:config.MAX_ALERTS_DISPLAYED]:
        sev      = alert.get("severity", config.SEVERITY_LOW)
        color    = SEVERITY_COLORS.get(sev, "white")
        icon     = SEVERITY_ICONS.get(sev, "⚪")
        ts       = datetime.fromtimestamp(alert.get("timestamp", 0)).strftime("%H:%M:%S")
        desc     = alert.get("description", "")

        # Truncate long descriptions for display
        if len(desc) > 60:
            desc = desc[:57] + "..."

        table.add_row(
            ts,
            Text(f"{icon} {sev}",   style=color),
            Text(alert.get("alert_type", ""),   style=color),
            Text(alert.get("client_id", ""),    style="cyan"),
            Text(desc,                          style=color)
        )

    return table


def build_stats_panel():
    """Summary statistics panel."""
    with lock:
        total_msgs   = counters["total_messages"]
        alert_counts = dict(counters["alerts_by_severity"])
        elapsed      = time.time() - counters["start_time"]

    rate = total_msgs / elapsed if elapsed > 0 else 0
    total_alerts = sum(alert_counts.values())

    stats_text = Text()
    stats_text.append(f"Total Messages: {total_msgs:,}   ", style="white")
    stats_text.append(f"Avg Rate: {rate:.1f}/sec   ", style="cyan")
    stats_text.append(f"Total Alerts: {total_alerts}   ", style="bold red" if total_alerts > 0 else "green")
    stats_text.append("| Severity: ", style="dim")
    for sev, count in alert_counts.items():
        color = SEVERITY_COLORS.get(sev, "white")
        icon  = SEVERITY_ICONS.get(sev, "⚪")
        stats_text.append(f"{icon}{count} ", style=color)

    return Panel(stats_text, title="📊 Statistics", box=box.ROUNDED, style="blue")


def build_legend_panel():
    """Quick-reference legend for alert severity levels."""
    text = Text()
    text.append("🔵 LOW ", style="bright_blue")
    text.append("— Info/Audit  ", style="dim")
    text.append("🟡 MEDIUM ", style="yellow")
    text.append("— Investigate  ", style="dim")
    text.append("🔴 HIGH ", style="red")
    text.append("— Respond Now  ", style="dim")
    text.append("💀 CRITICAL ", style="bold red")
    text.append("— Immediate Action  ", style="dim")
    text.append("| Red device ID = UNAUTHORISED", style="bold red")

    return Panel(text, title="🔑 Legend", box=box.SIMPLE, style="dim")


# ─────────────────────────────────────────────────────────────────────────────
# FUNCTION: render_dashboard
# Assembles all components into the final dashboard layout.
# Called every DASHBOARD_REFRESH_RATE seconds by Rich's Live context.
# ─────────────────────────────────────────────────────────────────────────────
def render_dashboard():
    from rich.console import Group
    return Group(
        build_header(),
        build_stats_panel(),
        build_device_table(),
        build_alerts_table(),
        build_legend_panel(),
    )


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    console = Console()

    console.print("\n[bold cyan]🛡️  IoT Attack Detection Lab — Dashboard[/bold cyan]")
    console.print("[dim]Connecting to MQTT broker and starting live display...[/dim]\n")

    # ── Start alert log tailer in background ─────────────────────────────
    tailer = threading.Thread(target=tail_alerts_log, daemon=True, name="AlertTailer")
    tailer.start()

    # ── Set up MQTT subscription for live device data ─────────────────────
    dash_client = mqtt.Client(client_id="dashboard-client")
    dash_client.on_connect = on_connect_dashboard
    dash_client.on_message = on_message_dashboard

    try:
        dash_client.connect(config.BROKER_HOST, config.BROKER_PORT, config.BROKER_KEEPALIVE)
        dash_client.loop_start()
    except ConnectionRefusedError:
        console.print("[red]❌ Cannot connect to broker. Start Mosquitto first.[/red]")
        console.print("[dim]   sudo systemctl start mosquitto[/dim]")
        sys.exit(1)

    console.print("[green]✅ Connected. Dashboard starting in 1 second...[/green]")
    console.print("[dim]   Press Ctrl+C to exit[/dim]\n")
    time.sleep(1)

    # ── Live display loop ─────────────────────────────────────────────────
    try:
        with Live(
            render_dashboard(),
            console=console,
            refresh_per_second=1.0 / config.DASHBOARD_REFRESH_RATE,
            screen=True     # Full-screen mode (clear terminal)
        ) as live:
            while True:
                live.update(render_dashboard())
                time.sleep(config.DASHBOARD_REFRESH_RATE)

    except KeyboardInterrupt:
        pass

    finally:
        dash_client.loop_stop()
        dash_client.disconnect()
        console.print("\n[cyan]👋 Dashboard closed.[/cyan]")


if __name__ == "__main__":
    main()
