# =============================================================================
# devices/device_runner.py — Launch ALL IoT Devices Simultaneously
# =============================================================================
# Instead of opening 4 separate terminals, run this single script to launch
# all device simulators in parallel using Python threads.
#
# Each device runs in its own thread, independently publishing to the broker.
# Think of each thread as a separate "physical device" on the network.
# =============================================================================

import threading    # Python's built-in threading module
import sys
import os
import time

# ── Add parent directory to import config ────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Import each device's main() function ─────────────────────────────────────
# We import the module and call its main() from a separate thread
from devices import temperature_sensor
from devices import door_sensor
from devices import motion_sensor
from devices import smart_light


# ─────────────────────────────────────────────────────────────────────────────
# FUNCTION: run_device
# Wrapper that runs a device's main() and catches any unhandled exceptions.
# This prevents one crashed device from killing all others.
# ─────────────────────────────────────────────────────────────────────────────
def run_device(device_module, device_name):
    try:
        print(f"[DeviceRunner] 🚀 Starting {device_name}...")
        device_module.main()
    except Exception as e:
        print(f"[DeviceRunner] ❌ {device_name} crashed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN: Create and start a thread for each device
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("  🏠 IoT Device Runner — Starting all virtual devices")
    print("=" * 60)
    print("  Press Ctrl+C to stop all devices\n")

    # Define each device as (module, display_name)
    devices = [
        (temperature_sensor, "Temperature Sensor (temp-sensor-01)"),
        (door_sensor,        "Door Sensor (door-sensor-01)"),
        (motion_sensor,      "Motion Sensor (motion-sensor-01)"),
        (smart_light,        "Smart Light (smart-light-01)"),
    ]

    threads = []

    for module, name in devices:
        # daemon=True means the thread will die when the main program exits
        # This ensures Ctrl+C cleanly stops everything
        t = threading.Thread(
            target=run_device,
            args=(module, name),
            daemon=True,
            name=name
        )
        threads.append(t)
        t.start()
        # Small stagger to avoid simultaneous broker connections
        time.sleep(0.5)

    print(f"\n[DeviceRunner] ✅ {len(threads)} devices running.")
    print("[DeviceRunner] 📡 Publishing to MQTT broker...")
    print("[DeviceRunner] ⌨️  Press Ctrl+C to stop all devices\n")

    # ── KEEP MAIN THREAD ALIVE ─────────────────────────────────────────────
    # Without this, the main thread would exit immediately and the daemon
    # threads would be killed before they do any work.
    try:
        while True:
            # Check if any threads have died unexpectedly
            alive_count = sum(1 for t in threads if t.is_alive())
            if alive_count < len(threads):
                print(f"[DeviceRunner] ⚠️  Only {alive_count}/{len(threads)} devices running")
            time.sleep(10)  # Status check every 10 seconds

    except KeyboardInterrupt:
        print("\n[DeviceRunner] 🛑 Shutdown signal received.")
        print("[DeviceRunner] Waiting for devices to disconnect cleanly...")
        # Daemon threads will stop automatically when main exits
        time.sleep(2)
        print("[DeviceRunner] 👋 All devices stopped.")


if __name__ == "__main__":
    main()
