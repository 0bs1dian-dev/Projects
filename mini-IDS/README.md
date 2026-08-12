# Network IDS & Traffic Detector (Python / Scapy)

An embryonic, lightweight **Intrusion Detection System (IDS)** developed in Python. The tool captures live network traffic on the local network interface, analyzes packet structures at the IP and TCP/UDP layers, and applies security rules to detect potential threats or configuration anomalies.

Generated alerts are printed to the terminal and logged into a structured log file (JSON), ready to be indexed by SIEM systems (e.g., Splunk or ELK Stack).

## 🚀 Key Features

* **Live Packet Sniffing:** Real-time network traffic capture leveraging the low-level capabilities of the `Scapy` library.
* **Essential Deep Packet Inspection (DPI):** Packet parsing to extract source/destination IP addresses and transport ports (TCP/UDP).
* **Unsecure Protocol Detection:** Monitoring standard unencrypted ports (`80` HTTP, `21` FTP, `23` Telnet) to flag unencrypted data in transit.
* **Port Scan Detection (Stateful Logic):** Uses in-memory data structures to track the number of unique ports targeted by a single IP address. A critical alert is triggered if the configured threshold is exceeded (Default: 10).
* **SIEM-Ready Logging:** Automatic export of alerts in structured JSON format, complete with timestamps and severity levels (`MEDIUM` / `HIGH`).

## 🛠️ Technical Requirements

The project requires Python 3.x and the `Scapy` library.

```bash
pip install scapy

```

> ⚠️ **Note on permissions:** To put the network interface into promiscuous mode and capture low-level packets, administrator/root privileges are required by the operating system.

## 💻 How to Use

1. Clone the repository and navigate to the project directory.
2. Run the script with elevated privileges:

```bash
# On Linux / macOS
sudo python sniffer.py

# On Windows (Run Command Prompt or PowerShell as Administrator)
python sniffer.py

```

### How to Simulate Alerts (Testing)

* **To test unencrypted traffic detection:** Send a standard HTTP request from another terminal:

```bash
curl http://neverssl.com

```

* **To test Port Scan detection:** Run an automated scan (e.g., using Nmap against your host) or make rapid connections to different ports.

## 📊 Log Structure (JSON Output)

Alerts are written in real time to the `security_alerts.json` file. Each event follows a standardized structure:

```json
{
  "timestamp": "2026-06-06 21:50:12",
  "severity": "MEDIUM",
  "alert_type": "INSECURE_PROTOCOL",
  "details": {
    "src_ip": "192.168.1.15",
    "dst_ip": "1.1.1.1",
    "port": 80,
    "protocol": "HTTP"
  }
}

```

## 📸 Screenshots

### Execution

### Log File

## 📈 Future Developments

* [ ] Implementation of multi-threading to prevent packet loss on high-traffic networks.
* [ ] Integration of advanced detection rules based on standardized **Sigma** or **Snort** formats.
* [ ] Analysis of DNS query logs to identify connection attempts to malicious domains (DGA/C2).

---

Developed for educational and portfolio purposes within the Cybersecurity field.
