# 🛡️ SentinelDrop 
### Autonomous Threat Intelligence & Static Analysis Engine  

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.13-blue?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/Platform-Windows%2011-success?style=for-the-badge&logo=windows" />
  <img src="https://img.shields.io/badge/Status-Active-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Focus-Cybersecurity-red?style=for-the-badge" />
</p>

---

# 📌 Project Overview

**SentinelCore** is an event-driven cybersecurity system designed to provide **real-time protection against malicious file downloads** through automated monitoring, static malware analysis, and intelligent quarantine operations.

Developed as part of my cybersecurity studies, SentinelCore continuously monitors file-system activity across multiple drives and performs local threat analysis using heuristic detection techniques inspired by modern endpoint protection systems.

The system is optimized for lightweight execution on Windows environments while maintaining rapid response capabilities against suspicious executable files.

---

# 🚀 Core Features

## 🔍 Real-Time Event Monitoring
- Uses the Windows API `ReadDirectoryChangesW`
- Monitors:
  - File creation
  - File modification
  - File renaming
- Supports monitoring across multiple drives such as:
  - `C:\`
  - `D:\`

---

## 🧬 Local Static Analysis Engine
SentinelCore performs lightweight static malware analysis by inspecting file “DNA”, including:

- PE Header Analysis
- Suspicious Import Detection
- File Entropy Analysis
- Executable Signature Inspection
- Hash-Based Integrity Tracking

This allows the engine to identify:
- Packed executables
- Obfuscated payloads
- Suspicious binaries
- Potential malware droppers

---

## 🚨 Autonomous Quarantine System
When a file exceeds the configured danger threshold:

- The file is automatically isolated
- Moved into a secure quarantine directory
- Renamed using unique identifiers
- Protected from accidental execution

This minimizes user interaction and reduces infection risk.

---

## ⚡ Deduplication & Cooldown Logic
Windows file systems can generate rapid repetitive events.

SentinelCore includes:
- Event deduplication
- Cooldown timers
- Queue stabilization logic

This improves:
- Performance
- Reliability
- Alert accuracy
- System stability

---

## 📧 Automated Security Alerting
The engine automatically sends detailed threat notifications via SMTP.

Each report may include:
- File name
- SHA-256 hash
- Threat score
- Detection reason
- Timestamp
- Quarantine location

---

# 🛠️ Technical Stack

| Component | Technology |
|---|---|
| Language | Python 3.13 |
| Platform | Windows 11 |
| API Integration | pywin32 |
| Static Analysis | pefile |
| Hashing | hashlib |
| Background Execution | Windows Task Scheduler |

---

# 🧠 Detection Workflow

```text
[ File Event Triggered ]
            ↓
[ Extension Filtering ]
            ↓
[ SHA-256 Hash Generation ]
            ↓
[ Static Analysis Engine ]
            ↓
[ Heuristic Evaluation ]
            ↓
[ Risk Score Calculation ]
            ↓
 ┌───────────────┬───────────────┐
 │ Safe File     │ Suspicious    │
 │ Allow Access  │ Quarantine    │
 └───────────────┴───────────────┘
            ↓
[ SMTP Alert Notification ]
```

---

# 🔬 Analysis Methodology

## 1️⃣ Event Capture
The system listens for high-risk file types such as:

```text
.exe
.dll
.zip
.bat
.scr
.ps1
```

---

## 2️⃣ Hashing
Generates SHA-256 hashes for:
- Integrity verification
- Threat tracking
- Duplicate detection

---

## 3️⃣ Heuristic Evaluation
The local analysis engine evaluates indicators such as:

- High entropy values
- Suspicious PE imports
- Executable anomalies
- Known malicious patterns
- Packed binary behavior

---

## 4️⃣ Threat Quarantine
If the calculated risk exceeds the safety threshold:

- File access is blocked
- File is relocated
- Threat is isolated
- Alert is generated

---

# ⚙️ Deployment

SentinelCore is designed to run as a lightweight background resident service.

### Deployment Method
- Windows Task Scheduler
- High-privilege execution
- Automatic startup on boot

---

# 🎯 Project Objectives

The goal of SentinelCore is to demonstrate:

- Real-time defensive programming
- Windows API integration
- Malware analysis fundamentals
- Threat detection automation
- Secure file handling
- Event-driven cybersecurity architecture

---

# 📚 Educational Purpose

This project was developed for:
- Cybersecurity learning
- Malware analysis research
- Defensive security experimentation
- Static analysis practice

It is intended strictly for **educational and defensive purposes only**.

---

# 🔒 Future Improvements

- YARA rule integration
- Machine learning threat scoring
- Live dashboard monitoring
- Multi-threaded scanning engine
- Sandbox execution support
- Cloud reputation API integration
- Behavioral analysis engine

---

# 👨‍💻 Author

**Chuah Ming Yuan**  
Cybersecurity Student  

---

# ⭐ Repository Goals

If you find this project interesting, feel free to:
- Star the repository
- Fork the project
- Suggest improvements
- Contribute to development

---

# ⚠️ Disclaimer

SentinelCore is a research and educational project.  
It should not replace enterprise-grade antivirus or EDR solutions in production environments.
