# Pure Hash Identifier (Python / Regex Engine)

A high-speed cryptographic identification engine developed in Python. This tool was created to support the initial triage phase during Penetration Testing or CTF activities, allowing analysts to instantly recognize unknown hash types before passing them to dedicated cracking tools like *Hashcat* or *John the Ripper*.

## 🚀 Key Features

* **Zero Dependencies:** Built exclusively using Python's native `re` (Regular Expressions) module. No extra packages or network connection required.
* **Extended Signature Database:** Accurate recognition of the most common formats in Information Security (Operating Systems, Databases, CMS, and network devices).
* **Ambiguity Handling:** Identifies when a string structure matches multiple algorithms (e.g., the structural overlap between MD5 and Windows NTLM), displaying all plausible candidates.

## 📊 Supported Algorithms

* **Operating Systems:** Windows LM/NTLM, Linux `bcrypt`
* **Global Standards:** MD5, SHA-1, SHA-256, SHA-512
* **Databases & CMS:** MySQL 4.1+, WordPress (`phpass`)
* **Networking:** Cisco Type 7

## 💻 Installation & Usage

```bash
# Clone the project and run the script
python hash_id.py

```

## 📊 Sample Output

```text
[?] Enter the hash to identify: 21232f297a57a5a743894a0e4a801fc3

[*] Structural analysis completed. Detected 2 possible candidate(s):

 🎯 [TYPE]: MD5
    └── ℹ️ Details: Legacy algorithm (32 hexadecimal characters). Very common, vulnerable to collisions.

 🎯 [TYPE]: NTLM / LM (Windows)
    └── ℹ️ Details: Microsoft Windows local/domain authentication hash (SAM database and Active Directory).

```

---

Developed as a command-line utility tool for Ethical Hacking and Log Analysis activities.
