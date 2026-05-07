# SentinelCore: Autonomous Threat Intelligence & Static Analysis Engine

![Python Version](https://img.shields.io/badge/python-3.13-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%2011-lightgrey.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

**SentinelCore** is an event-driven, autonomous file security system designed to provide real-time protection against malicious downloads. Developed as a core project during my Cybersecurity studies at Asia Pacific University (APU), this system moves beyond simple API calls to implement local heuristic analysis and proactive threat isolation.

---

## 🛡️ Key Features

- **Real-Time Drive Monitoring**: Hooks into the Windows API (`ReadDirectoryChangesW`) to monitor `Downloads`, `Desktop`, and custom drives (e.g., `D:\`) simultaneously.
- **Autonomous Quarantine**: Detected threats are immediately neutralized by moving them to a secure, isolated directory with obfuscated filenames to prevent accidental execution.
- **Static Analysis Engine**: Evaluates file "DNA" by analyzing PE headers, calculating file entropy, and checking SHA-256 integrity.
- **Zero-Footprint Operation**: Optimized to run as a windowless background process (`pythonw.exe`) on modern hardware like the Huawei MateBook D 15.
- **Email Intelligence Alerts**: Sends structured security reports via SMTP, including file hashes and detection details for rapid incident response.

---

## 🛠️ Technical Stack

- **Core**: Python 3.13
- **API Hooks**: `pywin32` (Windows System Calls)
- **Analysis**: `pefile`, `hashlib`, `os`
- **Security**: `python-dotenv` (Environment Secret Management)

---

## 🚀 Getting Started

### Prerequisites
- Windows 10/11
- Python 3.13+
- Gmail App Password (for SMTP alerts)

### Installation
1. **Clone the repository**:
   ```bash
   git clone [https://github.com/](https://github.com/)[Your-GitHub-Username]/SentinelCore.git
   cd SentinelCore
Setup Environment Variables:
Create a .env file in the root directory (refer to .env.example):

Plaintext
GEMINI_API_KEY=your_key_here
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_app_password
Install Dependencies:

Bash
pip install -r requirements.txt
Run the System:

Bash
pythonw.exe index.pyw
📂 System Architecture
Plaintext
SentinelCore/
├── logs/               # Secure execution logs
├── quarantine/         # Isolated threat storage
├── .env.example        # Configuration template
├── index.pyw           # Background monitor engine
└── README.md           # Project documentation
🛡️ Security Disclaimer
This project is for educational and research purposes only. It was developed to demonstrate malware analysis techniques and system-level monitoring. The author is not responsible for any damage caused by the misuse of this software. Always test in a controlled virtual environment.

👨‍💻 Author
[Chuah Ming Yuan] Cybersecurity Student Focus: Reverse Engineering | Network Architecture | IoT Security

