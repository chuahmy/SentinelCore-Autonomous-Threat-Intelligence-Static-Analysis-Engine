SentinelCore: Autonomous Threat Intelligence & Static Analysis Engine
🛡️ Project Overview
SentinelCore is an event-driven cybersecurity system designed to provide real-time protection against malicious file downloads. Developed as part of my cybersecurity studies at Asia Pacific University (APU), the system monitors file-system activity across multiple drives (C: and D:) to detect, analyze, and quarantine high-risk files using local static analysis and AI-driven heuristics.

🚀 Key Features
Real-Time Event Monitoring: Utilizes the Windows API (ReadDirectoryChangesW) to hook into system-wide file events (Created, Modified, Renamed).

Local Static Analysis: Evaluates file "DNA" including PE headers, imports, and file entropy to detect packed or suspicious executables.

Autonomous Quarantine System: Automatically moves threats to a secured, isolated directory and renames them with unique identifiers to prevent accidental execution.

Deduplication & Cooldown Logic: Implements custom logic to handle rapid-fire OS file events, ensuring system stability and reducing alert fatigue.

Automated Alerting: Sends detailed security reports via SMTP, providing immediate notification of quarantined threats.

🛠️ Technical Stack
Language: Python 3.13.

Operating System: Windows 11 (Optimized for Huawei MateBook D 15).

Libraries: pywin32 (Windows API), pefile (Static Analysis), hashlib (Data Integrity).

Deployment: Background resident service managed via Windows Task Scheduler for high-privilege execution.

🛡️ Analysis Methodology
Event Capture: The system listens for high-risk extensions like .exe, .zip, and .dll.

Hashing: Generates SHA-256 signatures for file integrity tracking.

Heuristic Evaluation: (Your local AI/YARA logic goes here).

Quarantine: Moves the file to an isolated path if the danger level exceeds the threshold.

📈 Future Roadmap
