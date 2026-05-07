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

# 🖥️ Automatic Startup (Background Protection)

To ensure SentinelCore automatically protects your system every time you log in to Windows, follow the steps below.

---

## 1️⃣ Create a Shortcut

1. Locate your `index.pyw` file.
2. Right-click the file.
3. Select:

```text
Show more options → Create shortcut
```

---

## 2️⃣ Enable Administrator Privileges

1. Right-click the newly created shortcut.
2. Select:

```text
Properties
```

3. Under the **Shortcut** tab, click:

```text
Advanced...
```

4. Enable:

```text
☑ Run as administrator
```

5. Click **OK**.

> ⚠️ Administrator privileges are required for SentinelCore to monitor system-level file activity across multiple drives.

---

## 3️⃣ Move Shortcut to Startup Folder

1. Press:

```text
Win + R
```

2. Type:

```text
shell:startup
```

3. Press **Enter**.

4. Copy or move the modified shortcut into the Startup folder.

---

## 4️⃣ Verify Background Execution

After your next login:

- Windows may prompt for administrator permission.
- Accept the prompt to launch SentinelCore.
- The scanner will run silently in the background.

### To verify:
1. Open **Task Manager**
2. Go to:

```text
Details
```

3. Look for:

```text
pythonw.exe
```

If visible, SentinelCore is actively running in the background.

---

# 🔒 Security Note

SentinelCore operates locally and does not upload scanned files externally unless explicitly configured for cloud integrations or SMTP alerting.

👨‍💻 Author
[Chuah Ming Yuan] Cybersecurity Student Focus: Reverse Engineering | Network Architecture | IoT Security

