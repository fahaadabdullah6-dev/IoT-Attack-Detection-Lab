# 🛡️ IoT Attack Detection Lab — MQTT Security Monitor

> **Academic Research Project** | MSc Cybersecurity → PhD Application Portfolio    
> **Author:** [Fahad Ali] | [fahaadabdullah6@gmail.com]

A fully simulated IoT network with real attack scenarios and a live detection engine.  
Built to demonstrate hands-on competency in IoT protocol security, anomaly detection,  
and SIEM integration (Microsoft Sentinel).

---

## 📐 Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        IoT ATTACK DETECTION LAB                         │
│                                                                         │
│  ┌──────────────┐    MQTT     ┌─────────────────┐    MQTT               │
│  │  IoT DEVICES │ ──publish──▶│  MOSQUITTO      │◀── subscribe ──┐      │
│  │              │             │  BROKER         │                │      │
│  │ 🌡 Temp Sensor│             │  (localhost:1883)│                │      │
│  │ 🚪 Door Sensor│             └────────┬────────┘                │      │
│  │ 👁 Motion Sen │                      │                         │      │
│  │ 💡 Smart Light│                      │ all traffic             │      │
│  └──────────────┘                      │                         │      │
│                                        ▼                         │      │
│  ┌──────────────┐             ┌─────────────────┐                │      │
│  │   ATTACKS    │             │  DETECTION      │                │      │
│  │              │             │  ENGINE         │                │      │
│  │ ⚡ DoS Flood  │──injects──▶│                 │                │      │
│  │ 👤 Spoofing   │             │ • Rate limiting │                │      │
│  │ 👂 Sniffing   │──listens───┘ • Payload check │                │      │
│  └──────────────┘             │ • Topic audit   │                │      │
│                               │ • Auth monitor  │                │      │
│                               └────────┬────────┘                │      │
│                                        │                         │      │
│                          ┌─────────────▼──────────┐              │      │
│                          │      ALERT PIPELINE     │              │      │
│                          │                         │              │      │
│                          │  📄 logs/alerts.log     │              │      │
│                          │  📊 Terminal Dashboard  │──────────────┘      │
│                          │  ☁️  Microsoft Sentinel  │                     │
│                          │     (Log Analytics API) │                     │
│                          └─────────────────────────┘                     │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
IoT-Attack-Detection-Lab/
│
├── README.md                   ← You are here
├── requirements.txt            ← Python dependencies
├── config.py                   ← Central configuration (broker, topics, thresholds)
│
├── devices/                    ← Simulated IoT device publishers
│   ├── temperature_sensor.py   ← Publishes temp readings every N seconds
│   ├── door_sensor.py          ← Publishes open/close events
│   ├── motion_sensor.py        ← Publishes motion detection events
│   ├── smart_light.py          ← Publishes on/off/brightness state
│   └── device_runner.py        ← Launches ALL devices simultaneously
│
├── attacks/                    ← Attack simulation scripts
│   ├── dos_flood.py            ← MQTT message flood (DoS attack)
│   ├── mqtt_spoof.py           ← Device identity spoofing attack
│   └── eavesdrop.py            ← Passive topic subscription sniffing
│
├── detection/                  ← Security monitoring engine
│   ├── monitor.py              ← Core MQTT traffic monitor + alert dispatcher
│   ├── anomaly_detector.py     ← Anomaly detection logic & severity scoring
│   └── sentinel_forwarder.py   ← Optional: forward alerts to Microsoft Sentinel
│
├── dashboard/
│   └── terminal_dashboard.py   ← Live terminal UI (device status + alerts)
│
└── logs/
    ├── alerts.log              ← Generated at runtime — all detected events
    └── .gitkeep                ← Keeps folder in git when logs are empty
```

---

## ⚙️ Prerequisites & Setup

### 1. Install Mosquitto MQTT Broker

**On Kali Linux / Ubuntu:**
```bash
sudo apt update
sudo apt install mosquitto mosquitto-clients -y
sudo systemctl start mosquitto
sudo systemctl enable mosquitto
```

**On Windows:**
- Download from https://mosquitto.org/download/
- Install and start the service via Services panel

**Verify broker is running:**
```bash
mosquitto -v        # verbose test run
# OR check service:
sudo systemctl status mosquitto
```

### 2. Configure Mosquitto (allow anonymous connections for lab)

Edit `/etc/mosquitto/mosquitto.conf` (Linux) or `C:\Program Files\mosquitto\mosquitto.conf` (Windows):
```
listener 1883
allow_anonymous true
```
Then restart: `sudo systemctl restart mosquitto`

### 3. Clone & Install Python Dependencies

```bash
git clone https://github.com/YOUR_USERNAME/IoT-Attack-Detection-Lab.git
cd IoT-Attack-Detection-Lab

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate          # Linux/Mac
venv\Scripts\activate             # Windows

# Install dependencies
pip install -r requirements.txt
```

### 4. (Optional) Configure Microsoft Sentinel

If you want to forward alerts to Azure Sentinel:
1. Create a Log Analytics Workspace in Azure Portal
2. Copy the **Workspace ID** and **Primary Key**
3. Add them to `config.py`:
   ```python
   SENTINEL_WORKSPACE_ID = "your-workspace-id"
   SENTINEL_PRIMARY_KEY  = "your-primary-key"
   ```

---

## 🚀 Running the Lab

Open **4 separate terminals** (or tmux panes):

### Terminal 1 — Start all IoT Devices
```bash
python devices/device_runner.py
```

### Terminal 2 — Start the Detection Engine
```bash
python detection/monitor.py
```

### Terminal 3 — Launch the Live Dashboard
```bash
python dashboard/terminal_dashboard.py
```

### Terminal 4 — Run Attack Simulations (one at a time)
```bash
# DoS Flood Attack
python attacks/dos_flood.py

# Spoofing Attack
python attacks/mqtt_spoof.py

# Eavesdropping Attack
python attacks/eavesdrop.py
```

---

## ⚔️ Attack Scenarios Explained

### 1. 🔥 DoS Flood Attack (`dos_flood.py`)
**What it does:** Rapidly publishes thousands of messages to the broker, exhausting  
broker resources and preventing legitimate devices from communicating.

**Real-world parallel:** Mirai botnet flooding IoT devices with traffic.

**Detection method:** The monitor counts messages per client per second. If any  
client exceeds `MAX_MESSAGES_PER_SECOND` (configurable in `config.py`), a  
HIGH severity alert is raised.

**Wireshark filter to observe it:**
```
tcp.port == 1883 && mqtt
```

---

### 2. 👤 MQTT Spoofing Attack (`mqtt_spoof.py`)
**What it does:** Pretends to be a legitimate IoT device (same topic, fake device ID)  
and publishes malicious or misleading sensor data.

**Real-world parallel:** A rogue device injecting false temperature readings to  
trigger HVAC systems or disable fire alarms.

**Detection method:** The monitor validates payload structure/format against a  
known schema. Unexpected fields, out-of-range values, or unrecognised client  
IDs trigger a MEDIUM/HIGH severity alert.

---

### 3. 👂 Eavesdropping / Sniffing (`eavesdrop.py`)
**What it does:** Subscribes to ALL topics on the broker using a wildcard (`#`),  
silently capturing every message published — including sensitive device data.

**Real-world parallel:** An attacker on the same network passively reading  
all unencrypted MQTT data (e.g., door lock status, occupancy data).

**Detection method:** The monitor tracks subscriber lists. Any client subscribing  
to broad wildcards (`#` or `+`) that isn't in the authorised subscriber list  
triggers a LOW/MEDIUM severity alert.

**Note:** In a real deployment, TLS + authentication would prevent this. This lab  
demonstrates the risk of unencrypted MQTT (port 1883).

---

## 🔬 Research Context

This project explores the following research themes relevant to Dr. Khan's work:

| Theme | Implementation |
|-------|---------------|
| IoT Protocol Vulnerabilities | MQTT v3.1.1 without TLS demonstrated |
| Anomaly-Based Intrusion Detection | Statistical rate analysis + schema validation |
| SIEM Integration | Azure Sentinel Log Analytics API forwarding |
| Attack Taxonomy | DoS, Spoofing, Eavesdropping modelled from MITRE ATT&CK IoT |

**Planned extensions (PhD scope):**
- ML-based anomaly detection (Isolation Forest / LSTM autoencoder)
- TLS/mTLS enforcement + certificate pinning demo
- MQTT v5 security features evaluation
- Network topology simulation with GNS3

---

## 🛠️ Troubleshooting

| Problem | Solution |
|---------|----------|
| `Connection refused` on port 1883 | Start Mosquitto broker first |
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` |
| Dashboard not updating | Ensure `monitor.py` is running in another terminal |
| Alerts not appearing | Check `logs/alerts.log` is writable |
| Sentinel not receiving | Verify Workspace ID + Key in `config.py` |

---

## 📚 References

- OASIS MQTT v3.1.1 Specification: https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/
- MITRE ATT&CK for ICS: https://attack.mitre.org/matrices/ics/
- Paho MQTT Python Client: https://github.com/eclipse/paho.mqtt.python
- Microsoft Sentinel Log Analytics API: https://docs.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api

---

## 📄 License

MIT License — Free to use for academic and research purposes.

---

*Built as part of PhD application portfolio demonstrating practical IoT security research capability.*
