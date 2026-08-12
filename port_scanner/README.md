# Modular Vulnerability Scanner & Recon Framework (Python / Live NIST API)

An automated command-line interface (CLI) **Vulnerability Assessment** framework developed in Python. The tool performs active reconnaissance on specified targets, identifies the status of transport ports (TCP Connect Scan), executes *Banner Grabbing*, and correlates collected information in real time with globally indexed known vulnerabilities.

Unlike static scanning tools, this script connects directly via API to the U.S. government's **NVD (National Vulnerability Database) hosted by NIST**, pulling the latest **CVEs** (Common Vulnerabilities and Exposures) updated in real time.

## 🚀 Key Features

* **Native TCP Port Scanner:** Built exclusively using Python's standard `socket` library, eliminating heavy external dependencies.
* **Smart Banner Grabbing:** Interception and cleaning of identification strings exposed by network services (e.g., OpenSSH, Apache, etc.).
* **Live Threat Intelligence Integration:** Direct connection to the National Vulnerability Database (NVD) REST API v2 to query matches based on keywords and software versions.
* **Automated Markdown Reporting:** Automatic generation of a professionally formatted Markdown audit report (`report_[target].md`), structured and ready to share with development or management teams.
* **Robust CLI Parsing:** Flexible input parameter handling via the `argparse` library (standard format for Linux security tools).

## 🛠️ Technical Requirements

The project uses native Python modules, with the exception of the `requests` library for handling external API calls.

```bash
pip install requests

```

## 💻 How to Use

The tool requires the target host (`-t` or `--target`) as a mandatory parameter, which can be an IP address or domain you have permission to audit.

```bash
# Scan local system
python scanner.py -t 127.0.0.1

# Scan a specific host on the LAN
python scanner.py -t 192.168.1.50

```

### Available Parameters:

* `-h`, `--help`: Show the help screen with command syntax.
* `-t TARGET`, `--target TARGET`: Specify the target IP address or domain.

## 📊 Sample Generated Report (`.md`)

The output file is formatted automatically. Below is an example of how `report_127_0_0_1.md` appears when a service with known vulnerabilities is detected:

---

# 🛡️ Vulnerability Assessment Report

**Analyzed Target:** `192.168.176.130`

**Scan Date:** 2026-06-06 17:24:05

---

### 🚪 Port 22 - OPEN

* **Detected Banner:** `SSH-2.0-OpenSSH_10.3p1 Debian-1`

#### 🚨 Identified Critical Vulnerabilities (NIST NVD):

* **CVE-2007-0726**
* *Description:* The SSH key generation process in OpenSSH in Apple Mac OS X 10.3.9 and 10.4 through 10.4.8 allows remote attackers to cause a denial of service by con...


* **CVE-2026-35385**
* *Description:* In OpenSSH before 10.3, a file downloaded by scp may be installed setuid or setgid, an outcome contrary to some users' expectations, if the download i...


* **CVE-2026-35386**
* *Description:* In OpenSSH before 10.3, command execution can occur via shell metacharacters in a username within a command line. This requires a scenario where the u...



---

## 📈 Future Developments

* [ ] Multi-threading implementation for simultaneous scanning of entire network ranges (e.g., CIDR /24).
* [ ] Automatic conversion of banner strings into standardized **CPE (Common Platform Enumeration)** format for 100% query precision.
* [ ] Support for advanced UDP scanning.

---

Developed for educational purposes and as an automated reconnaissance tool for Ethical Hacking activities.
