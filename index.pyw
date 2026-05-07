import os
import re
import time
import hashlib
import requests
import smtplib
import threading
import shutil
import logging
from datetime import datetime
from email.mime.text import MIMEText
from dotenv import load_dotenv
from google import genai
import win32file
import win32con

# ================= INITIALIZATION & CONFIG =================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, '.env'))

QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")
os.makedirs(QUARANTINE_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(BASE_DIR, "scanner.log"), encoding="utf-8"),
        logging.StreamHandler()
    ]
)

VT_API_KEY     = os.getenv("VT_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
EMAIL_SENDER   = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER")

MAJOR_ENGINES   = ["microsoft", "kaspersky", "bitdefender", "malwarebytes", "eset-nod32"]
SCAN_EXTENSIONS = {'.exe', '.dll', '.msi', '.bat', '.ps1', '.vbs', '.zip', '.7z', '.rar', '.pdf'}

# enter your own folders to watch here (add more if you want). Subfolders will be auto-scanned.

FOLDERS_TO_WATCH = [
    #e.g. FOLDERS_TO_WATCH = [r"C:\Users\YourName\Downloads", r"C:\Users\YourName\Desktop"]
]
# ==========================================================


# ================= STARTUP GRACE PERIOD ===================
STARTUP_TIME     = time.time()
STARTUP_GRACE    = 30   # extra seconds buffer on top of startup time

def _is_preexisting_file(filepath):
    """Returns True if the file existed before this script started."""
    try:
        mtime = os.path.getmtime(filepath)
        return mtime < (STARTUP_TIME - STARTUP_GRACE)
    except Exception:
        return False
# ==========================================================


# ================= THREAD-SAFE DEDUPLICATION ==============
_dedup_lock  = threading.Lock()
_dedup_cache = {}       # sha256_hash -> timestamp
DEDUP_WINDOW = 60       # seconds

def _already_processed(file_hash):
    """Returns True if this hash was already processed within DEDUP_WINDOW. Thread-safe."""
    with _dedup_lock:
        now       = time.time()
        last_seen = _dedup_cache.get(file_hash, 0)
        if now - last_seen < DEDUP_WINDOW:
            return True
        _dedup_cache[file_hash] = now
        return False
# ==========================================================


def get_sha256_hash(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(65536), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        logging.error(f"Hashing error for {filepath}: {e}")
        return f"Error: {e}"


def check_virustotal(file_hash):
    url     = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=30)

        if response.status_code == 200:
            data              = response.json()
            scans             = data.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
            detected_list     = []
            major_av_detected = False

            for engine, scan_data in scans.items():
                if scan_data.get('category') == 'malicious':
                    detected_list.append({
                        "engine":       engine,
                        "malware_name": scan_data.get('result', 'Unknown Threat')
                    })
                    if any(major in engine.lower() for major in MAJOR_ENGINES):
                        major_av_detected = True

            total = len(detected_list)
            if total == 0:
                return {"status": "CLEAR",   "color": "#28a745", "detections": detected_list, "total": total}
            elif major_av_detected or total >= 5:
                return {"status": "DANGER",  "color": "#dc3545", "detections": detected_list, "total": total}
            else:
                return {"status": "WARNING", "color": "#ffc107", "detections": detected_list, "total": total}

        elif response.status_code == 404:
            return {"status": "UNKNOWN", "color": "#6c757d", "detections": [], "total": 0}
        else:
            return {"status": "ERROR",   "color": "#6c757d", "detections": [], "total": 0}

    except Exception as e:
        logging.error(f"VT check error: {e}")
        return {"status": "ERROR", "color": "#6c757d", "detections": [], "total": 0}


def upload_to_virustotal(filepath):
    """Uploads a previously unseen file to VT for fresh analysis."""
    logging.info(f"Uploading to VT: {filepath}")

    if os.path.getsize(filepath) > 32 * 1024 * 1024:
        logging.warning("File > 32MB. Skipping upload.")
        return {"status": "UNKNOWN", "color": "#6c757d", "detections": [], "total": 0}

    url     = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VT_API_KEY}

    try:
        with open(filepath, "rb") as f:
            response = requests.post(
                url, headers=headers,
                files={"file": (os.path.basename(filepath), f)},
                timeout=60
            )

        if response.status_code != 200:
            logging.error(f"VT upload failed: HTTP {response.status_code}")
            return {"status": "ERROR", "color": "#6c757d", "detections": [], "total": 0}

        analysis_id = response.json().get("data", {}).get("id")
        logging.info(f"Uploaded. Polling VT (ID: {analysis_id})...")

        for attempt in range(10):
            time.sleep(15)
            poll   = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers, timeout=30
            )
            status = poll.json().get("data", {}).get("attributes", {}).get("status")
            logging.info(f"VT analysis: {status} (attempt {attempt + 1}/10)")

            if status == "completed":
                file_hash = poll.json().get("meta", {}).get("file_info", {}).get("sha256")
                if file_hash:
                    return check_virustotal(file_hash)
                break

        return {"status": "ERROR", "color": "#6c757d", "detections": [], "total": 0}

    except Exception as e:
        logging.error(f"VT upload error: {e}")
        return {"status": "ERROR", "color": "#6c757d", "detections": [], "total": 0}


def quarantine_file(filepath):
    """Moves a dangerous file into the quarantine folder."""
    try:
        filename  = os.path.basename(filepath)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        dest      = os.path.join(QUARANTINE_DIR, f"{timestamp}_{filename}")
        shutil.move(filepath, dest)
        logging.warning(f"[!!!] QUARANTINED: {filepath} -> {dest}")
        return dest
    except Exception as e:
        logging.error(f"Quarantine failed for {filepath}: {e}")
        return None


def analyze_with_ai(filename, detections):
    if not detections:
        return "No threats detected. File is clean."

    client = genai.Client(api_key=GEMINI_API_KEY)
    prompt = f"""
You are a cybersecurity malware analyst. I downloaded a file named '{filename}'.
It was scanned by VirusTotal and flagged by the following engines:
{detections}

Please provide:
1. Is this a FALSE POSITIVE (e.g. game crack/repack) or TRUE MALWARE? Be direct.
2. What malware family/type is it based on the threat names?
3. How dangerous is it (1-10)?

Keep your response to 2 sentences maximum. End with 1-2 real reference URLs only (no fabricated links).
"""

    for attempt in range(3):
        try:
            response = client.models.generate_content(
                model='gemini-2.5-flash',
                contents=prompt
            )
            return response.text
        except Exception as e:
            err = str(e).lower()
            if "429" in err or "quota" in err:
                logging.warning(f"Gemini rate limit. Waiting 20s (attempt {attempt + 1}/3)...")
                time.sleep(20)
            elif "503" in err or "unavailable" in err:
                logging.warning(f"Gemini unavailable. Waiting 10s (attempt {attempt + 1}/3)...")
                time.sleep(10)
            else:
                return f"AI analysis failed: {e}"

    return "AI analysis unavailable: rate limit exceeded after retries."


def send_email_alert(filepath, file_hash, vt_data, ai_verdict, quarantine_path=None):
    """Sends a full HTML email alert including the detected file path."""
    filename   = os.path.basename(filepath)
    status     = vt_data.get('status', 'ERROR')
    color      = vt_data.get('color', '#6c757d')
    detections = vt_data.get('detections', [])
    total      = vt_data.get('total', 0)
    scanned_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Detection table
    if detections:
        rows = "".join(
            f"<tr>"
            f"<td style='padding:8px; border:1px solid #ddd;'><strong>{item['engine']}</strong></td>"
            f"<td style='padding:8px; border:1px solid #ddd; color:#dc3545;'>{item['malware_name']}</td>"
            f"</tr>"
            for item in detections
        )
        table_html = f"""
        <table style='border-collapse:collapse; width:100%; margin-top:10px;'>
            <tr style='background-color:#f2f2f2;'>
                <th style='text-align:left; padding:8px; border:1px solid #ddd;'>Engine</th>
                <th style='text-align:left; padding:8px; border:1px solid #ddd;'>Threat Name</th>
            </tr>
            {rows}
        </table>
        """
    else:
        table_html = "<p>No active threats detected.</p>"

    # Quarantine notice
    quarantine_html = ""
    if quarantine_path:
        quarantine_html = f"""
        <div style='background-color:#f8d7da; padding:15px; border-left:4px solid #dc3545; margin-top:20px; border-radius:3px;'>
            <h3 style='margin-top:0; color:#dc3545;'>⚠️ FILE AUTO-QUARANTINED</h3>
            <p style='margin-bottom:0;'>Moved to:<br>
            <span style='font-family:monospace; font-size:13px;'>{quarantine_path}</span></p>
        </div>
        """

    # Make AI verdict URLs clickable
    ai_verdict_html = re.sub(
        r'(https?://[^\s<>"]+)',
        r'<a href="\1" style="color:#0d6efd;">\1</a>',
        ai_verdict.replace('\n', '<br>')
    )

    html_content = f"""
    <html>
    <body style='font-family:Arial, sans-serif; line-height:1.6; color:#333; max-width:800px; margin:auto;'>
        <div style='border:2px solid {color}; padding:20px; border-radius:5px;'>

            <h2 style='color:{color}; margin-top:0;'>SCAN STATUS: {status}</h2>

            <table style='width:100%; border-collapse:collapse;'>
                <tr>
                    <td style='padding:5px 0; width:130px; vertical-align:top;'><strong>File Name</strong></td>
                    <td style='padding:5px 0;'>{filename}</td>
                </tr>
                <tr>
                    <td style='padding:5px 0; vertical-align:top;'><strong>File Path</strong></td>
                    <td style='padding:5px 0;'>
                        <span style='font-family:monospace; font-size:13px; background:#f1f1f1; padding:2px 6px; border-radius:3px;'>
                            {filepath}
                        </span>
                    </td>
                </tr>
                <tr>
                    <td style='padding:5px 0; vertical-align:top;'><strong>SHA-256</strong></td>
                    <td style='padding:5px 0;'>
                        <span style='font-family:monospace; font-size:12px;'>{file_hash}</span>
                    </td>
                </tr>
                <tr>
                    <td style='padding:5px 0;'><strong>Scanned At</strong></td>
                    <td style='padding:5px 0;'>{scanned_at}</td>
                </tr>
                <tr>
                    <td style='padding:5px 0;'><strong>Detections</strong></td>
                    <td style='padding:5px 0;'>{total} engine(s) flagged</td>
                </tr>
            </table>

            {quarantine_html}

            <div style='background-color:#f8f9fa; padding:15px; border-left:4px solid #0d6efd; margin-top:20px; border-radius:3px;'>
                <h3 style='margin-top:0; color:#0d6efd;'>🤖 AI Analyst Verdict</h3>
                <p style='margin-bottom:0;'>{ai_verdict_html}</p>
            </div>

            <hr style='border:1px solid #eee; margin-top:20px;'>
            <h3>Detection Details</h3>
            {table_html}

        </div>
    </body>
    </html>
    """

    msg            = MIMEText(html_content, 'html')
    msg['Subject'] = f'[{status}] VT Alert: {filename}'
    msg['From']    = EMAIL_SENDER
    msg['To']      = EMAIL_RECEIVER

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)
        logging.info(f"Email sent for {filename}")
    except smtplib.SMTPAuthenticationError:
        logging.error("Email auth failed. Check EMAIL_SENDER and EMAIL_PASSWORD in .env")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")


def wait_for_download_completion(filepath):
    """Waits until file size is stable (download finished)."""
    historical_size = -1
    stable_count    = 0

    while True:
        try:
            if not os.path.exists(filepath):
                return False
            current_size = os.path.getsize(filepath)
            if current_size == historical_size and current_size > 0:
                stable_count += 1
                if stable_count >= 2:
                    time.sleep(1)
                    return True
            else:
                stable_count = 0
            historical_size = current_size
            time.sleep(2)
        except Exception:
            time.sleep(2)


def process_new_file(filepath):
    """Full scan pipeline: wait → hash → dedup check → VT → quarantine → AI → email."""

    # Never re-scan files that were moved into quarantine
    if QUARANTINE_DIR.lower() in filepath.lower():
        return

    filename = os.path.basename(filepath)

    # Skip files that already existed before this script started
    # This prevents re-scanning leftover files on every reboot
    if _is_preexisting_file(filepath):
        logging.info(f"Skipped pre-existing file (existed before startup): {filename}")
        return

    if not wait_for_download_completion(filepath):
        logging.warning(f"File gone before scan: {filepath}")
        return

    logging.info(f"Hashing: {filename}")
    file_hash = get_sha256_hash(filepath)
    if file_hash.startswith("Error"):
        return

    # DEDUP CHECK — blocks duplicate emails for the same file
    # even when multiple folder watchers fire simultaneously
    if _already_processed(file_hash):
        logging.info(f"Duplicate skipped (same hash already processed): {filename}")
        return

    logging.info(f"Checking VirusTotal for: {filename}")
    vt_data = check_virustotal(file_hash)

    if vt_data.get("status") == "UNKNOWN":
        vt_data = upload_to_virustotal(filepath)

    quarantine_path = None
    if vt_data.get("status") == "DANGER":
        quarantine_path = quarantine_file(filepath)

    ai_verdict = "File is clean. No AI analysis required."
    if isinstance(vt_data.get('total'), int) and vt_data.get('total', 0) > 0:
        logging.info("Threats found. Querying AI...")
        ai_verdict = analyze_with_ai(filename, vt_data['detections'])
        logging.info(f"AI Verdict: {ai_verdict}")

    send_email_alert(filepath, file_hash, vt_data, ai_verdict, quarantine_path)


def monitor_folder(path):
    """Watches a folder (and subfolders) for new or modified scannable files."""
    if not os.path.exists(path):
        logging.error(f"Path does not exist, skipping: {path}")
        return

    try:
        hDir = win32file.CreateFile(
            path,
            win32con.GENERIC_READ,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_BACKUP_SEMANTICS,
            None
        )
    except Exception as e:
        logging.error(f"Cannot open handle for {path}: {e}")
        return

    logging.info(f"Watching: {path}")

    while True:
        try:
            results = win32file.ReadDirectoryChangesW(
                hDir,
                65536,
                True,   # recursive
                win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                win32con.FILE_NOTIFY_CHANGE_SIZE      |
                win32con.FILE_NOTIFY_CHANGE_LAST_WRITE,
                None,
                None
            )

            for action, filename in results:
                # action: 1=created, 3=modified, 5=renamed-to
                if action not in [1, 3, 5]:
                    continue

                full_path = os.path.join(path, filename)
                ext       = os.path.splitext(filename)[1].lower()

                # Skip temp browser download files
                if any(x in filename.lower() for x in ['.tmp', '.crdownload', '.part']):
                    continue

                # Skip non-risky extensions
                if ext not in SCAN_EXTENSIONS:
                    continue

                # Skip anything inside quarantine
                if QUARANTINE_DIR.lower() in full_path.lower():
                    continue

                thread = threading.Thread(
                    target=process_new_file,
                    args=(full_path,),
                    daemon=True
                )
                thread.start()

        except Exception as e:
            logging.error(f"Monitor error on {path}: {e}")
            time.sleep(2)


if __name__ == "__main__":
    logging.info("=" * 55)
    logging.info("  VTScanner - AI-Powered Real-Time File Monitor")
    logging.info("=" * 55)

    # Validate all required env vars on startup
    required = ["VT_API_KEY", "GEMINI_API_KEY", "EMAIL_SENDER", "EMAIL_PASSWORD", "EMAIL_RECEIVER"]
    missing  = [k for k in required if not os.getenv(k)]
    if missing:
        logging.error(f"Missing .env variables: {missing}")
        input("Press Enter to exit...")
        raise SystemExit(1)

    threads = []
    for folder in FOLDERS_TO_WATCH:
        t = threading.Thread(target=monitor_folder, args=(folder,), daemon=True)
        t.start()
        threads.append(t)

    logging.info("System armed. Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Shutting down VTScanner...")
