#
##########################################################################################################
#███████╗████████╗ ██████╗ ██████╗       ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     #
#██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗      ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     #
#███████╗   ██║   ██║   ██║██████╔╝      ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     #
#╚════██║   ██║   ██║   ██║██╔═══╝       ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     #
#███████║   ██║   ╚██████╔╝██║           ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗#
#╚══════╝   ╚═╝    ╚═════╝ ╚═╝           ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝#
##########################################################################################################

#
##########################################################################################
#__  __      ___  _     ___   _____  ___   ___   ___  __  __ #
#\ \/ /     | _ \| |   / _ \ |_   _|| __| / _ \ | _ \|  \/  |#
# >  <      |  _/| |_ / /_\ \  | |  | _| | (_) ||   /| |\/| |#
#/_/\_\     |_|  |___|\_/ \_/  |_|  |_|   \___/ |_|_\|_|  |_|#
###########################################################################################
# stop_sentinel.py - Cross-platform version

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import ctypes
from ctypes import wintypes
import threading
import datetime
import json
import csv
import time
import platform
import subprocess
import re
import os
import math
import hashlib
import smtplib
import socket
import logging
import logging.handlers
from collections import defaultdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict, field
from enum import Enum
from http.server import HTTPServer, BaseHTTPRequestHandler

try:
    from cryptography.fernet import Fernet
    HAS_CRYPTO = True
    print("[OK] cryptography loaded")
except ImportError as e:
    HAS_CRYPTO = False
    print(f"[WARN] cryptography not installed: {e}")

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import pystray
    from PIL import Image, ImageDraw
    HAS_TRAY = True
except ImportError:
    HAS_TRAY = False

SYSTEM = platform.system()
APP_DIR = Path(__file__).parent
HOOKS_FILE = APP_DIR / "hooks.dlp"
LOGS_DIR = APP_DIR / "stop_sentinel_logs"
CONFIG_FILE = APP_DIR / "stop_sentinel_config.json"
KEY_FILE = APP_DIR / "stop_sentinel.key"
HISTORY_FILE = APP_DIR / "stop_sentinel_history.enc"

LOGS_DIR.mkdir(exist_ok=True)

if SYSTEM == "Windows":
    DLL_PATH = APP_DIR / "promptsec_hook.dll"
elif SYSTEM == "Darwin":
    DLL_PATH = APP_DIR / "stop_sentinel_hook.dylib"
else:
    DLL_PATH = APP_DIR / "stop_sentinel_hook.so"

WM_USER = 0x0400
WM_THREAT_DETECTED = WM_USER + 100
CF_UNICODETEXT = 13

if SYSTEM == "Windows":
    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    if ctypes.sizeof(ctypes.c_void_p) == 8:
        LRESULT = ctypes.c_int64
        WPARAM = ctypes.c_uint64
        LPARAM = ctypes.c_int64
    else:
        LRESULT = ctypes.c_long
        WPARAM = ctypes.c_uint
        LPARAM = ctypes.c_long

    WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, WPARAM, LPARAM)

    class WNDCLASSEXW(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.UINT), ("style", wintypes.UINT),
            ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int),
            ("cbWndExtra", ctypes.c_int), ("hInstance", wintypes.HINSTANCE),
            ("hIcon", wintypes.HICON), ("hCursor", wintypes.HANDLE),
            ("hbrBackground", wintypes.HBRUSH), ("lpszMenuName", wintypes.LPCWSTR),
            ("lpszClassName", wintypes.LPCWSTR), ("hIconSm", wintypes.HICON),
        ]

    user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, WPARAM, LPARAM]
    user32.DefWindowProcW.restype = LRESULT


class ThreatLevel(Enum):
    CRITICAL = "#dc2626"
    HIGH = "#ea580c"
    MEDIUM = "#f59e0b"
    LOW = "#3b82f6"
    INFO = "#6b7280"


@dataclass
class SecurityPattern:
    name: str
    pattern: str
    threat_level: ThreatLevel
    description: str
    enabled: bool = True
    is_builtin: bool = True
    pattern_type: str = "substring"


@dataclass
class AuditEvent:
    timestamp: str
    event_type: str
    source_app: str
    threat: str
    level: str
    action: str
    score: float = 0.0


@dataclass
class ClipboardHistoryEntry:
    timestamp: str
    content_hash: str
    preview: str
    source_app: str
    threat_detected: bool
    threat_name: str = ""

#----------------
# DASHBOARD
#----------------

class DashboardServer:
    def __init__(self, logs_dir, encryption, port=8080):
        self.logs_dir = logs_dir
        self.encryption = encryption
        self.port = port
        self.server = None
        self.thread = None
        self.running = False

    def start(self):
        if self.running:
            return True

        enc = self.encryption
        logs_dir = self.logs_dir
        server_ref = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                events = []
                for f in sorted(logs_dir.glob("audit_*.jsonl")):
                    try:
                        with open(f, 'r') as file:
                            for line in file:
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    events.append(json.loads(line))
                                except Exception:
                                    try:
                                        d = enc.decrypt(line)
                                        events.append(json.loads(d))
                                    except Exception:
                                        pass
                    except Exception:
                        pass

                today = datetime.date.today().isoformat()
                today_events = [e for e in events if e.get("timestamp", "").startswith(today)]
                threats = [e for e in today_events if e.get("event_type") == "THREAT"]

                rows = ""
                for e in list(reversed(events))[:50]:
                    lv = e.get("level", "INFO")
                    bc = "badge-crit" if lv == "CRITICAL" else "badge-high" if lv == "HIGH" else ""
                    rows += (f"<tr><td>{e.get('timestamp','')[:19]}</td>"
                             f"<td>{e.get('event_type','')}</td>"
                             f"<td>{e.get('source_app','')[:30]}</td>"
                             f"<td>{e.get('threat','')[:40]}</td>"
                             f"<td><span class='badge {bc}'>{lv}</span></td>"
                             f"<td>{e.get('action','')}</td>"
                             f"<td>{e.get('score', 0)}</td></tr>")

                html = f"""<!DOCTYPE html><html><head>
<title>STOP Sentinel Dashboard</title>
<meta http-equiv="refresh" content="30">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0}}
.hdr{{background:#1e293b;padding:20px;text-align:center}}
.hdr h1{{color:#38bdf8}}.hdr p{{color:#64748b;margin-top:5px}}
.wrap{{max-width:1200px;margin:20px auto;padding:0 20px}}
.card{{background:#1e293b;border-radius:8px;padding:20px;margin:10px 0}}
.stats{{display:flex;justify-content:center;gap:40px}}
.st{{text-align:center}}.st .v{{font-size:36px;font-weight:bold;color:#38bdf8}}
.st .l{{color:#94a3b8;font-size:13px}}.st .v.red{{color:#ef4444}}
table{{width:100%;border-collapse:collapse;margin-top:10px}}
th,td{{padding:8px 10px;text-align:left;border-bottom:1px solid #334155}}
th{{color:#94a3b8;font-size:11px;text-transform:uppercase}}
.badge{{padding:2px 6px;border-radius:3px;font-size:10px;font-weight:bold}}
.badge-crit{{background:#dc2626;color:#fff}}.badge-high{{background:#ea580c;color:#fff}}
</style></head><body>
<div class="hdr"><h1>STOP Sentinel Dashboard</h1>
<p>Auto-refreshes every 30 seconds</p></div>
<div class="wrap">
<div class="card"><div class="stats">
<div class="st"><div class="v">{len(events)}</div><div class="l">Total Events</div></div>
<div class="st"><div class="v">{len(today_events)}</div><div class="l">Today</div></div>
<div class="st"><div class="v red">{len(threats)}</div><div class="l">Threats Blocked</div></div>
</div></div>
<div class="card"><h3>Recent Events</h3>
<table><tr><th>Time</th><th>Type</th><th>Source</th><th>Threat</th>
<th>Level</th><th>Action</th><th>Score</th></tr>{rows}</table>
</div></div></body></html>"""

                self.send_response(200)
                self.send_header("Content-type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(html.encode('utf-8'))

            def log_message(self, format, *args):
                pass

        try:
            self.server = HTTPServer(("127.0.0.1", self.port), Handler)
            self.running = True
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()
            return True
        except Exception as e:
            print(f"[DASHBOARD ERROR] {e}")
            return False

    def stop(self):
        if self.server and self.running:
            self.server.shutdown()
            self.server = None
            self.running = False

    def is_running(self):
        return self.running

# ================================
# CONFIG
# ================================
class ConfigManager:
    DEFAULT = {
        "email": {"enabled": False, "smtp_server": "smtp.gmail.com", "smtp_port": 587,
                  "username": "", "password": "", "from_addr": "", "to_addrs": "",
                  "use_tls": True, "rate_limit_seconds": 60},
        "remote_sync": {"enabled": False, "url": "", "interval_minutes": 60, "auth_token": ""},
        "auto_update": {"enabled": False,
                        "repo_url": "https://raw.githubusercontent.com/shuvrobasu/stop_sentinel/main/hooks.dlp",
                        "check_interval_hours": 24},
        "encryption": {"enabled": True},
        "clipboard": {"auto_expire_seconds": 30, "auto_expire_enabled": False,
                      "history_enabled": True, "history_max_entries": 500},
        "whitelist": {"enabled": True, "apps": ["Visual Studio Code", "PyCharm", "IntelliJ"]},
        "app_rules": {
            "Slack": {"block": True, "alert": True, "level": "CRITICAL"},
            "Discord": {"block": True, "alert": True, "level": "CRITICAL"},
            "Microsoft Teams": {"block": True, "alert": True, "level": "CRITICAL"},
        },
        "entropy": {"enabled": True, "threshold": 4.5, "min_length": 20},
        "siem": {"enabled": False, "host": "127.0.0.1", "port": 514,
                 "protocol": "UDP", "facility": 1, "format": "CEF"},
        "undo": {"enabled": True, "pin": "0000", "expire_seconds": 300},
        "team_dashboard": {"enabled": False, "port": 8443, "api_key": ""}
    }

    def __init__(self):
        self.config = self._load()

    def _load(self) -> dict:
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, 'r') as f:
                    loaded = json.load(f)
                merged = json.loads(json.dumps(self.DEFAULT))
                for section in merged:
                    if section in loaded:
                        if isinstance(merged[section], dict):
                            merged[section].update(loaded[section])
                        else:
                            merged[section] = loaded[section]
                return merged
            except:
                pass
        return json.loads(json.dumps(self.DEFAULT))

    def save(self):
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            print(f"[CONFIG ERROR] {e}")

    def get(self, section, key=None, default=None):
        if key is None:
            return self.config.get(section, default)
        return self.config.get(section, {}).get(key, default)

    def set(self, section, key, value):
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = value
        self.save()


# ================================
# ENCRYPTION
# ================================
class EncryptionManager:
    def __init__(self, enabled=True):
        self.enabled = enabled and HAS_CRYPTO
        self.fernet = None
        if self.enabled:
            self._init_key()

    def _init_key(self):
        try:
            if KEY_FILE.exists():
                with open(KEY_FILE, 'rb') as f:
                    key = f.read()
            else:
                key = Fernet.generate_key()
                with open(KEY_FILE, 'wb') as f:
                    f.write(key)
                if SYSTEM != "Windows":
                    os.chmod(KEY_FILE, 0o600)
            self.fernet = Fernet(key)
        except:
            self.enabled = False

    def encrypt(self, text):
        if not self.enabled or not self.fernet:
            return text
        try:
            return self.fernet.encrypt(text.encode()).decode()
        except:
            return text

    def decrypt(self, text):
        if not self.enabled or not self.fernet:
            return text
        try:
            return self.fernet.decrypt(text.encode()).decode()
        except:
            return text


# ================================
# LUHN VALIDATOR
# ================================
class LuhnValidator:
    @staticmethod
    def is_valid(number_str: str) -> bool:
        digits = [int(c) for c in number_str if c.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False
        checksum = 0
        reverse = digits[::-1]
        for i, d in enumerate(reverse):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
        return checksum % 10 == 0

    @staticmethod
    def extract_and_validate(text: str) -> List[str]:
        found = []
        pattern = re.compile(r'\b[\d]{4}[\s-]?[\d]{4}[\s-]?[\d]{4}[\s-]?[\d]{4}\b')
        for match in pattern.finditer(text):
            card = match.group()
            digits_only = re.sub(r'[\s-]', '', card)
            if LuhnValidator.is_valid(digits_only):
                found.append(card)
        return found


# ================================
# ENTROPY DETECTOR
# ================================
class EntropyDetector:
    def __init__(self, threshold=4.5, min_length=20):
        self.threshold = threshold
        self.min_length = min_length

    def calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        freq = defaultdict(int)
        for c in text:
            freq[c] += 1
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            prob = count / length
            if prob > 0:
                entropy -= prob * math.log2(prob)
        return entropy

    def find_high_entropy(self, text: str) -> List[Tuple[str, float]]:
        results = []
        words = re.split(r'[\s,;:=\'"]+', text)
        for word in words:
            clean = word.strip()
            if len(clean) >= self.min_length:
                ent = self.calculate_entropy(clean)
                if ent >= self.threshold:
                    results.append((clean[:50], round(ent, 2)))
        return results


# ================================
# THREAT SCORER
# ================================
class ThreatScorer:
    def __init__(self, entropy_detector: EntropyDetector):
        self.entropy = entropy_detector

    def score(self, text: str, pattern_name: str, threat_level: ThreatLevel) -> float:
        base_scores = {
            ThreatLevel.CRITICAL: 90,
            ThreatLevel.HIGH: 70,
            ThreatLevel.MEDIUM: 50,
            ThreatLevel.LOW: 30,
            ThreatLevel.INFO: 10
        }
        score = base_scores.get(threat_level, 50)

        # Entropy bonus
        ent = self.entropy.calculate_entropy(text[:100])
        if ent > 5.0:
            score += 10
        elif ent > 4.0:
            score += 5

        # Length bonus
        if len(text) > 100:
            score += 5

        # Known critical patterns
        critical_keywords = ["PRIVATE KEY", "AKIA", "ghp_", "sk_live_"]
        for kw in critical_keywords:
            if kw in text:
                score += 10
                break

        return min(score, 100)


# ================================
# SIEM INTEGRATION
# ================================
class SIEMForwarder:
    def __init__(self, config: ConfigManager):
        self.config = config

    def forward(self, event: AuditEvent):
        if not self.config.get("siem", "enabled"):
            return

        host = self.config.get("siem", "host", "127.0.0.1")
        port = self.config.get("siem", "port", 514)
        protocol = self.config.get("siem", "protocol", "UDP")
        fmt = self.config.get("siem", "format", "CEF")

        try:
            if fmt == "CEF":
                message = self._format_cef(event)
            else:
                message = self._format_syslog(event)

            if protocol == "UDP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(message.encode(), (host, port))
                sock.close()
            elif protocol == "TCP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((host, port))
                sock.sendall(message.encode() + b'\n')
                sock.close()

        except Exception as e:
            print(f"[SIEM ERROR] {e}")

    def _format_cef(self, event: AuditEvent) -> str:
        severity_map = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 5, "LOW": 3, "INFO": 1}
        severity = severity_map.get(event.level, 5)
        return (f"CEF:0|StopSentinel|DLP|5.0|{event.event_type}|"
                f"{event.threat}|{severity}|"
                f"src={event.source_app} act={event.action} "
                f"rt={event.timestamp} cs1={event.threat}")

    def _format_syslog(self, event: AuditEvent) -> str:
        facility = self.config.get("siem", "facility", 1)
        severity_map = {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 4, "LOW": 5, "INFO": 6}
        severity = severity_map.get(event.level, 5)
        pri = facility * 8 + severity
        return (f"<{pri}>{event.timestamp} StopSentinel: "
                f"event={event.event_type} threat={event.threat} "
                f"source={event.source_app} action={event.action}")


# ================================
# UNDO MANAGER
# ================================
class UndoManager:
    def __init__(self, config: ConfigManager, encryption: EncryptionManager):
        self.config = config
        self.encryption = encryption
        self.history: List[dict] = []
        self.max_entries = 50

    def store(self, original_text: str, redacted_text: str, threat: str):
        if not self.config.get("undo", "enabled"):
            return

        entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "original": self.encryption.encrypt(original_text),
            "redacted": redacted_text[:100],
            "threat": threat,
            "expires": (datetime.datetime.now() + datetime.timedelta(
                seconds=self.config.get("undo", "expire_seconds", 300)
            )).isoformat()
        }

        self.history.insert(0, entry)
        if len(self.history) > self.max_entries:
            self.history = self.history[:self.max_entries]

    def retrieve(self, pin: str, index: int = 0) -> Optional[str]:
        if pin != self.config.get("undo", "pin", "0000"):
            return None

        self._cleanup_expired()

        if index >= len(self.history):
            return None

        entry = self.history[index]
        return self.encryption.decrypt(entry["original"])

    def _cleanup_expired(self):
        now = datetime.datetime.now().isoformat()
        self.history = [e for e in self.history if e["expires"] > now]

    def get_recent(self) -> List[dict]:
        self._cleanup_expired()
        safe = []
        for e in self.history:
            safe.append({
                "timestamp": e["timestamp"],
                "redacted": e["redacted"],
                "threat": e["threat"],
                "expires": e["expires"]
            })
        return safe


# ================================
# CLIPBOARD HISTORY
# ================================
class ClipboardHistory:
    def __init__(self, config: ConfigManager, encryption: EncryptionManager):
        self.config = config
        self.encryption = encryption
        self.entries: List[ClipboardHistoryEntry] = []
        self.max_entries = config.get("clipboard", "history_max_entries", 500)

    def add(self, text: str, source: str, threat_detected: bool, threat_name: str = ""):
        if not self.config.get("clipboard", "history_enabled"):
            return

        content_hash = hashlib.sha256(text.encode()).hexdigest()[:16]
        preview = text[:80].replace('\n', ' ')

        entry = ClipboardHistoryEntry(
            timestamp=datetime.datetime.now().isoformat(),
            content_hash=content_hash,
            preview=self.encryption.encrypt(preview),
            source_app=source,
            threat_detected=threat_detected,
            threat_name=threat_name
        )

        self.entries.insert(0, entry)
        if len(self.entries) > self.max_entries:
            self.entries = self.entries[:self.max_entries]

    def get_entries(self) -> List[dict]:
        result = []
        for e in self.entries:
            result.append({
                "timestamp": e.timestamp,
                "hash": e.content_hash,
                "preview": self.encryption.decrypt(e.preview),
                "source": e.source_app,
                "threat": e.threat_detected,
                "threat_name": e.threat_name
            })
        return result

    def clear(self):
        self.entries.clear()


# ================================
# EMAIL ALERTER
# ================================
class EmailAlerter:
    def __init__(self, config: ConfigManager):
        self.config = config
        self.last_sent = 0

    def send_alert(self, threat, source_app, timestamp, score=0):
        if not self.config.get("email", "enabled"):
            return
        now = time.time()
        if now - self.last_sent < self.config.get("email", "rate_limit_seconds", 60):
            return
        self.last_sent = now
        threading.Thread(target=self._send, args=(threat, source_app, timestamp, score), daemon=True).start()

    def _send(self, threat, source_app, timestamp, score):
        try:
            msg = MIMEMultipart()
            msg['From'] = self.config.get("email", "from_addr")
            msg['To'] = self.config.get("email", "to_addrs")
            msg['Subject'] = f"[STOP Sentinel] Threat: {threat} (Score: {score})"

            body = (f"STOP Sentinel Alert\n{'=' * 40}\n\n"
                    f"Time: {timestamp}\nThreat: {threat}\n"
                    f"Source: {source_app}\nScore: {score}/100\n"
                    f"Action: BLOCKED\n\n-- STOP Sentinel DLP Agent")
            msg.attach(MIMEText(body, 'plain'))

            server = self.config.get("email", "smtp_server")
            port = self.config.get("email", "smtp_port", 587)
            with smtplib.SMTP(server, port) as smtp:
                if self.config.get("email", "use_tls"):
                    smtp.starttls()
                smtp.login(self.config.get("email", "username"),
                           self.config.get("email", "password"))
                smtp.send_message(msg)
        except Exception as e:
            print(f"[EMAIL ERROR] {e}")


# ================================
# REMOTE SYNC & AUTO-UPDATE
# ================================
class RemoteSync:
    def __init__(self, config: ConfigManager):
        self.config = config

    def sync_policy(self) -> Optional[str]:
        if not HAS_REQUESTS:
            return "requests not installed"
        url = self.config.get("remote_sync", "url")
        if not url:
            return "No URL configured"
        try:
            headers = {}
            token = self.config.get("remote_sync", "auth_token")
            if token:
                headers['Authorization'] = f"Bearer {token}"
            r = requests.get(url, headers=headers, timeout=10)
            r.raise_for_status()
            with open(HOOKS_FILE, 'w', encoding='utf-8') as f:
                f.write(r.text)
            return None
        except Exception as e:
            return str(e)

    def auto_update_patterns(self) -> Optional[str]:
        if not HAS_REQUESTS or not self.config.get("auto_update", "enabled"):
            return "Disabled"
        url = self.config.get("auto_update", "repo_url")
        if not url:
            return "No URL"
        try:
            r = requests.get(url, timeout=10)
            r.raise_for_status()
            with open(HOOKS_FILE, 'w', encoding='utf-8') as f:
                f.write(r.text)
            return None
        except Exception as e:
            return str(e)

    def start_auto(self, callback):
        def loop():
            while True:
                interval = self.config.get("auto_update", "check_interval_hours", 24) * 3600
                time.sleep(interval)
                if self.config.get("auto_update", "enabled"):
                    err = self.auto_update_patterns()
                    if not err:
                        callback()
        threading.Thread(target=loop, daemon=True).start()


# ================================
# WHITELIST & APP RULES
# ================================
class AppPolicyManager:
    def __init__(self, config: ConfigManager):
        self.config = config

    def is_whitelisted(self, app_name: str) -> bool:
        if not self.config.get("whitelist", "enabled"):
            return False
        whitelist = self.config.get("whitelist", "apps", [])
        app_lower = app_name.lower()
        return any(w.lower() in app_lower for w in whitelist)

    def get_app_rule(self, app_name: str) -> Optional[dict]:
        rules = self.config.get("app_rules", default={})
        app_lower = app_name.lower()
        for rule_app, rule in rules.items():
            if rule_app.lower() in app_lower:
                return rule
        return None

    def should_block(self, app_name: str) -> bool:
        rule = self.get_app_rule(app_name)
        if rule:
            return rule.get("block", True)
        return True

    def should_alert(self, app_name: str) -> bool:
        rule = self.get_app_rule(app_name)
        if rule:
            return rule.get("alert", False)
        return False


# ================================
# AUDIT LOGGER
# ================================
class AuditLogger:
    def __init__(self, encryption: EncryptionManager):
        self.encryption = encryption

    def log(self, event: AuditEvent):
        path = LOGS_DIR / f"audit_{datetime.date.today()}.jsonl"
        try:
            line = json.dumps(asdict(event))
            encrypted = self.encryption.encrypt(line)
            with open(path, 'a', encoding='utf-8') as f:
                f.write(encrypted + '\n')
        except Exception as e:
            print(f"[LOG ERROR] {e}")

    def read_logs(self, date=None) -> List[dict]:
        events = []
        if date:
            files = [LOGS_DIR / f"audit_{date}.jsonl"]
        else:
            files = sorted(LOGS_DIR.glob("audit_*.jsonl"))
        for f in files:
            if not f.exists():
                continue
            try:
                with open(f, 'r', encoding='utf-8') as file:
                    for line in file:
                        line = line.strip()
                        if line:
                            decrypted = self.encryption.decrypt(line)
                            events.append(json.loads(decrypted))
            except:
                pass
        return events

    def export(self, output: str) -> bool:
        try:
            events = self.read_logs()
            if events:
                with open(output, 'w', newline='', encoding='utf-8') as f:
                    w = csv.DictWriter(f, fieldnames=events[0].keys())
                    w.writeheader()
                    w.writerows(events)
                return True
        except:
            pass
        return False

    def get_stats(self) -> dict:
        events = self.read_logs()
        today = datetime.date.today().isoformat()
        today_events = [e for e in events if e.get("timestamp", "").startswith(today)]

        stats = {
            "total_events": len(events),
            "today_events": len(today_events),
            "threats_today": len([e for e in today_events if e.get("event_type") == "THREAT"]),
            "by_level": defaultdict(int),
            "by_source": defaultdict(int),
            "by_threat": defaultdict(int),
            "hourly": defaultdict(int)
        }

        for e in today_events:
            if e.get("event_type") == "THREAT":
                stats["by_level"][e.get("level", "UNKNOWN")] += 1
                stats["by_source"][e.get("source_app", "Unknown")[:20]] += 1
                stats["by_threat"][e.get("threat", "Unknown")[:30]] += 1
                hour = e.get("timestamp", "")[:13]
                stats["hourly"][hour] += 1

        return stats


# ================================
# CLIPBOARD
# ================================
class Clipboard:
    @staticmethod
    def get_text() -> Optional[str]:
        if SYSTEM == "Windows":
            return Clipboard._get_windows()
        elif SYSTEM == "Darwin":
            return Clipboard._get_macos()
        return Clipboard._get_linux()

    @staticmethod
    def set_text(text: str) -> bool:
        if SYSTEM == "Windows":
            return Clipboard._set_windows(text)
        elif SYSTEM == "Darwin":
            return Clipboard._set_macos(text)
        return Clipboard._set_linux(text)

    @staticmethod
    def clear() -> bool:
        return Clipboard.set_text("")

    @staticmethod
    def _get_windows():
        try:
            if not user32.OpenClipboard(None):
                return None
            try:
                h = user32.GetClipboardData(CF_UNICODETEXT)
                if h:
                    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
                    kernel32.GlobalLock.restype = ctypes.c_void_p
                    p = kernel32.GlobalLock(h)
                    if p:
                        text = ctypes.wstring_at(p)
                        kernel32.GlobalUnlock(h)
                        return text
            finally:
                user32.CloseClipboard()
        except:
            pass
        return None

    @staticmethod
    def _get_windows():
        try:
            for retry in range(5):
                if user32.OpenClipboard(None):
                    try:
                        h = user32.GetClipboardData(CF_UNICODETEXT)
                        if h:
                            kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
                            kernel32.GlobalLock.restype = ctypes.c_void_p
                            p = kernel32.GlobalLock(h)
                            if p:
                                text = ctypes.wstring_at(p)
                                kernel32.GlobalUnlock(h)
                                return text
                    finally:
                        user32.CloseClipboard()
                    return None
                time.sleep(0.02)
        except:
            pass
        return None

    @staticmethod
    def _get_macos():
        try:
            r = subprocess.run(['pbpaste'], capture_output=True, text=True, timeout=2)
            return r.stdout if r.returncode == 0 else None
        except:
            return None

    @staticmethod
    def _set_windows(text):
        try:
            for retry in range(5):
                if user32.OpenClipboard(None):
                    try:
                        user32.EmptyClipboard()
                        data = (text + '\0').encode('utf-16-le')
                        h = kernel32.GlobalAlloc(0x0042, len(data))
                        if h:
                            kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
                            kernel32.GlobalLock.restype = ctypes.c_void_p
                            p = kernel32.GlobalLock(h)
                            if p:
                                ctypes.memmove(p, data, len(data))
                                kernel32.GlobalUnlock(h)
                                user32.SetClipboardData(CF_UNICODETEXT, h)
                                return True
                    finally:
                        user32.CloseClipboard()
                    return False
                time.sleep(0.02)
        except:
            pass
        return False


    @staticmethod
    def _set_macos(text):
        try:
            p = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE)
            p.communicate(text.encode())
            return p.returncode == 0
        except:
            return False

    @staticmethod
    def _get_linux():
        for cmd in [['xclip', '-selection', 'clipboard', '-o'], ['xsel', '--clipboard', '-o']]:
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
                if r.returncode == 0:
                    return r.stdout
            except:
                continue
        return None

    @staticmethod
    def _set_linux(text):
        for cmd in [['xclip', '-selection', 'clipboard'], ['xsel', '--clipboard', '-i']]:
            try:
                p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
                p.communicate(text.encode())
                if p.returncode == 0:
                    return True
            except:
                continue
        return False


    @staticmethod
    def get_window():
        if SYSTEM == "Windows":
            try:
                hwnd = user32.GetForegroundWindow()
                length = user32.GetWindowTextLengthW(hwnd)
                if length:
                    buf = ctypes.create_unicode_buffer(length + 1)
                    user32.GetWindowTextW(hwnd, buf, length + 1)
                    return buf.value
            except:
                pass
        elif SYSTEM == "Linux":
            try:
                r = subprocess.run(['xdotool', 'getactivewindow', 'getwindowname'],
                                   capture_output=True, text=True, timeout=2)
                if r.returncode == 0:
                    return r.stdout.strip()
            except:
                pass
        elif SYSTEM == "Darwin":
            try:
                r = subprocess.run(['osascript', '-e',
                                    'tell application "System Events" to get name of first application process whose frontmost is true'],
                                   capture_output=True, text=True, timeout=2)
                if r.returncode == 0:
                    return r.stdout.strip()
            except:
                pass
        return "Unknown"


# ================================
# PATTERN MANAGER
# ================================
class PatternManager:
    def __init__(self):
        self.patterns: Dict[str, SecurityPattern] = {}
        self._load_from_file()

    def _load_from_file(self):
        if not HOOKS_FILE.exists():
            return
        try:
            with open(HOOKS_FILE, 'r', encoding='utf-8') as f:
                for row in csv.DictReader(f):
                    name = row.get('name', '').strip()
                    pattern = row.get('pattern', '').strip()
                    if not name or not pattern:
                        continue
                    key = name.upper().replace(' ', '_').replace('-', '_')
                    try:
                        threat_level = ThreatLevel[row.get('threat_level', 'HIGH').strip().upper()]
                    except KeyError:
                        threat_level = ThreatLevel.HIGH
                    enabled = row.get('enabled', 'true').strip().lower() in ('true', '1', 'yes')
                    pattern_type = row.get('type', 'substring').strip().lower()
                    if pattern_type == 'regex':
                        try:
                            re.compile(pattern)
                        except re.error:
                            continue
                    self.patterns[key] = SecurityPattern(
                        name=name, pattern=pattern, threat_level=threat_level,
                        description=row.get('description', name).strip(),
                        enabled=enabled, is_builtin=True, pattern_type=pattern_type
                    )
            print(f"[OK] Loaded {len(self.patterns)} patterns")
        except Exception as e:
            print(f"[ERROR] {e}")

    def save_to_file(self):
        try:
            with open(HOOKS_FILE, 'w', newline='', encoding='utf-8') as f:
                w = csv.DictWriter(f, fieldnames=['name', 'pattern', 'threat_level', 'description', 'enabled', 'type'])
                w.writeheader()
                for p in self.patterns.values():
                    w.writerow({'name': p.name, 'pattern': p.pattern, 'threat_level': p.threat_level.name,
                                'description': p.description, 'enabled': 'true' if p.enabled else 'false',
                                'type': p.pattern_type})
            return True
        except:
            return False

    def add_pattern(self, name, pattern, level, desc, ptype="substring"):
        key = name.upper().replace(' ', '_').replace('-', '_')
        self.patterns[key] = SecurityPattern(name=name, pattern=pattern, threat_level=level,
                                              description=desc, enabled=True, is_builtin=False, pattern_type=ptype)
        return self.save_to_file()

    def set_enabled(self, key, enabled):
        if key in self.patterns:
            self.patterns[key].enabled = enabled

    def get_enabled(self):
        return [p for p in self.patterns.values() if p.enabled]

    def get_substring_patterns(self):
        return [p for p in self.patterns.values() if p.enabled and p.pattern_type == "substring"]

    def get_regex_patterns(self):
        return [p for p in self.patterns.values() if p.enabled and p.pattern_type == "regex"]

    def reload(self):
        self.patterns.clear()
        self._load_from_file()


# ================================
# REGEX SCANNER
# ================================
class RegexScanner:
    def __init__(self, patterns: PatternManager, luhn: LuhnValidator, entropy: EntropyDetector):
        self.patterns = patterns
        self.luhn = luhn
        self.entropy = entropy
        self.last_hash = ""

    def scan(self, text: str) -> Optional[Tuple[str, str, float]]:
        if not text:
            return None

        text_hash = hashlib.sha256(text.encode()).hexdigest()[:16]
        if text_hash == self.last_hash:
            return None

        redacted = text
        threats = []
        max_score = 0

        # Regex patterns
        for p in self.patterns.get_regex_patterns():
            try:
                if re.search(p.pattern, redacted, re.IGNORECASE):
                    redacted = re.sub(p.pattern, f"[BLOCKED:{p.name}]", redacted, flags=re.IGNORECASE)
                    threats.append(p.name)
            except:
                pass

        # Luhn credit card validation
        valid_cards = self.luhn.extract_and_validate(text)
        for card in valid_cards:
            if "BLOCKED" not in card:
                redacted = redacted.replace(card, "[BLOCKED:Valid Credit Card]")
                if "Valid Credit Card" not in threats:
                    threats.append("Valid Credit Card (Luhn)")

        # Entropy detection
        high_entropy = self.entropy.find_high_entropy(text)
        for word, ent_val in high_entropy:
            if word not in redacted or "BLOCKED" in word:
                continue
            already_caught = False
            for t in threats:
                if t in word or word in redacted.split("BLOCKED"):
                    already_caught = True
                    break
            if not already_caught:
                redacted = redacted.replace(word, f"[BLOCKED:High Entropy ({ent_val})]")
                threats.append(f"Entropy:{ent_val}")

        if threats:
            self.last_hash = ""
            return (redacted, ", ".join(threats), max_score)

        self.last_hash = text_hash
        return None


# ================================
# NATIVE HOOK
# ================================
class NativeHook:
    def __init__(self, callback):
        self.callback = callback
        self.dll = None
        self.hwnd = None
        self.running = False
        self._wndproc = None
        self._thread = None
        self._ready = threading.Event()

    def _load_dll(self):
        if not DLL_PATH.exists():
            print(f"[ERROR] Hook not found: {DLL_PATH}")
            return False
        try:
            if SYSTEM == "Windows":
                self.dll = ctypes.CDLL(str(DLL_PATH))
                self.dll.InitHook.argtypes = [wintypes.HWND, wintypes.UINT]
                self.dll.InitHook.restype = wintypes.BOOL
                self.dll.CleanupHook.argtypes = []
                self.dll.CleanupHook.restype = None
                self.dll.SetActive.argtypes = [wintypes.BOOL]
                self.dll.SetActive.restype = None
                self.dll.IsActive.argtypes = []
                self.dll.IsActive.restype = wintypes.BOOL
                self.dll.AddPattern.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.BOOL]
                self.dll.AddPattern.restype = wintypes.BOOL
                self.dll.ClearPatterns.argtypes = []
                self.dll.ClearPatterns.restype = None
                self.dll.GetPatternCount.argtypes = []
                self.dll.GetPatternCount.restype = ctypes.c_int
                self.dll.ForceCheck.argtypes = []
                self.dll.ForceCheck.restype = wintypes.BOOL
            else:
                self.dll = ctypes.CDLL(str(DLL_PATH))
                CB = ctypes.CFUNCTYPE(None, ctypes.c_char_p)
                self.dll.InitHook.argtypes = [CB]
                self.dll.InitHook.restype = ctypes.c_int
                self.dll.CleanupHook.argtypes = []
                self.dll.SetActive.argtypes = [ctypes.c_int]
                self.dll.IsActive.restype = ctypes.c_int
                self.dll.AddPattern.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
                self.dll.AddPattern.restype = ctypes.c_int
                self.dll.ClearPatterns.argtypes = []
                self.dll.GetPatternCount.restype = ctypes.c_int
                self.dll.ForceCheck.restype = ctypes.c_int
                self._ncb = CB(self._unix_cb)
            print("[OK] Hook loaded")
            return True
        except Exception as e:
            print(f"[HOOK ERROR] {e}")
            return False

    def _unix_cb(self, ptr):
        try:
            self.callback("THREAT", ptr.decode() if ptr else "Unknown")
        except:
            pass

    def load_patterns(self, patterns: List[SecurityPattern]) -> int:
        if not self.dll:
            return 0

        # Check if AddPatternEx exists
        has_ex = False
        try:
            self.dll.AddPatternEx.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR,
                                               wintypes.BOOL, ctypes.c_int]
            self.dll.AddPatternEx.restype = wintypes.BOOL
            has_ex = True
        except:
            pass

        self.dll.ClearPatterns()

        for p in patterns:
            if SYSTEM == "Windows":
                if has_ex:
                    ptype = 1 if p.pattern_type == "regex" else 0
                    self.dll.AddPatternEx(p.name, p.pattern, p.enabled, ptype)
                else:
                    self.dll.AddPattern(p.name, p.pattern, p.enabled)
            else:
                self.dll.AddPattern(p.name.encode(), p.pattern.encode(),
                                    1 if p.enabled else 0)

        count = self.dll.GetPatternCount()
        print(f"[OK] Loaded {count} patterns (substring + regex)")
        return count

    def start(self):
        if self.running:
            return
        if not self._load_dll():
            return
        self.running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._ready.wait(timeout=5)

    def _run(self):
        if SYSTEM == "Windows":
            self._run_win()
        else:
            self._run_unix()

    def _run_win(self):
        hInst = kernel32.GetModuleHandleW(None)
        cn = f"StopSentinel{int(time.time() * 1000)}"

        # Set up HeapFree for memory cleanup
        kernel32.GetProcessHeap.restype = wintypes.HANDLE
        kernel32.HeapFree.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID]
        kernel32.HeapFree.restype = wintypes.BOOL
        process_heap = kernel32.GetProcessHeap()

        def proc(hwnd, msg, wp, lp):
            if msg == WM_THREAT_DETECTED:
                try:
                    if wp:
                        s = ctypes.wstring_at(wp)
                        self.callback("THREAT", s)
                        try:
                            kernel32.HeapFree(process_heap, 0, wp)
                        except:
                            pass
                except Exception as e:
                    print(f"[CALLBACK ERROR] {e}")
                    self.callback("THREAT", "Unknown")
                return 0
            return user32.DefWindowProcW(hwnd, msg, WPARAM(wp), LPARAM(lp))

        self._wndproc = WNDPROC(proc)
        wc = WNDCLASSEXW()
        wc.cbSize = ctypes.sizeof(WNDCLASSEXW)
        wc.lpfnWndProc = self._wndproc
        wc.hInstance = hInst
        wc.lpszClassName = cn
        user32.RegisterClassExW(ctypes.byref(wc))

        self.hwnd = user32.CreateWindowExW(0, cn, "StopSentinel", 0, 0, 0, 0, 0,
                                           None, None, hInst, None)

        if not self.hwnd:
            print("[ERROR] Window creation failed")
            self._ready.set()
            return

        if not self.dll.InitHook(self.hwnd, WM_THREAT_DETECTED):
            print("[ERROR] InitHook failed")
            self._ready.set()
            return

        print("[OK] Hook started")
        self._ready.set()

        msg = wintypes.MSG()
        while self.running:
            r = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
            if r == 0 or r == -1:
                break
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

        if self.dll:
            self.dll.CleanupHook()

    def _run_unix(self):
        if not self.dll.InitHook(self._ncb):
            self._ready.set()
            return
        self._ready.set()
        while self.running:
            time.sleep(0.1)
        if self.dll:
            self.dll.CleanupHook()

    def set_active(self, active):
        if self.dll:
            self.dll.SetActive(1 if active else 0)

    def force_check(self):
        return bool(self.dll.ForceCheck()) if self.dll else False

    def stop(self):
        self.running = False
        if self.dll:
            self.dll.SetActive(0)
        if SYSTEM == "Windows" and self.hwnd:
            user32.PostMessageW(self.hwnd, 0x0012, 0, 0)


# ================================
# MAIN APP
# ================================
class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("S.T.O.P Sentinel - DLP Agent v2.0")
        self.root.geometry("1300x750")
        self.root.minsize(1100, 650)
        self.root.configure(bg="#f8fafc")

        # Core
        self.config = ConfigManager()
        self.encryption = EncryptionManager(self.config.get("encryption", "enabled", True))
        self.patterns = PatternManager()
        self.audit = AuditLogger(self.encryption)
        self.emailer = EmailAlerter(self.config)
        self.siem = SIEMForwarder(self.config)
        self.remote_sync = RemoteSync(self.config)
        self.app_policy = AppPolicyManager(self.config)
        self.entropy_detector = EntropyDetector(
            self.config.get("entropy", "threshold", 4.5),
            self.config.get("entropy", "min_length", 20)
        )
        self.luhn = LuhnValidator()
        self.scorer = ThreatScorer(self.entropy_detector)
        self.undo = UndoManager(self.config, self.encryption)
        self.clip_history = ClipboardHistory(self.config, self.encryption)
        self.regex_scanner = RegexScanner(self.patterns, self.luhn, self.entropy_detector)
        self.hook = NativeHook(self._on_event)

        self.active = False
        self.stats = {"blocked": 0, "start": None}
        self.tray_icon = None
        self._expire_timer = None
        self.dashboard = DashboardServer(LOGS_DIR, self.encryption,
                                          self.config.get("team_dashboard", "port", 8080))

        self._setup_styles()
        self._build_menu()
        self._build_ui()

        self.hook.start()
        time.sleep(0.3)
        # count = self.hook.load_patterns(self.patterns.get_substring_patterns())
        count = self.hook.load_patterns(self.patterns.get_enabled())
        print(f"[OK] {count} substring + {len(self.patterns.get_regex_patterns())} regex patterns ready")

        self.remote_sync.start_auto(lambda: self.root.after(0, self._reload))
        self._start_timers()
        self.root.protocol("WM_DELETE_WINDOW", self._minimize_to_tray)

        if HAS_TRAY:
            self._create_tray_icon()

        try:
            if SYSTEM == "Windows":
                icon = APP_DIR / "icon.ico"
                if icon.exists():
                    self.root.iconbitmap(str(icon))
            else:
                icon = APP_DIR / "icon.png"
                if icon.exists():
                    img = tk.PhotoImage(file=str(icon))
                    self.root.iconphoto(True, img)
        except:
            pass

    def _create_tray_icon(self):
        try:
            img = Image.new('RGB', (64, 64), '#0f172a')
            dc = ImageDraw.Draw(img)
            dc.rectangle((8, 8, 56, 56), fill='#38bdf8')
            dc.text((20, 20), "S", fill='#0f172a')
            menu = pystray.Menu(
                pystray.MenuItem("Show", self._show_from_tray, default=True),
                pystray.MenuItem("Toggle", self._tray_toggle, checked=lambda item: self.active),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Exit", self._quit_app)
            )
            self.tray_icon = pystray.Icon("stop_sentinel", img, "STOP Sentinel", menu)
        except:
            pass

    def _minimize_to_tray(self):
        self.root.withdraw()
        if self.tray_icon and not self.tray_icon.visible:
            threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def _show_from_tray(self, icon=None, item=None):
        self.root.deiconify()
        self.root.lift()

    def _tray_toggle(self, icon, item):
        self.root.after(0, self._toggle)

    def _quit_app(self, icon=None, item=None):
        if self.tray_icon:
            try:
                self.tray_icon.stop()
            except:
                pass
        self.hook.stop()
        self.root.quit()
        self.root.destroy()

    def _setup_styles(self):
        s = ttk.Style()
        s.theme_use('clam')
        s.configure("Treeview", font=("Consolas", 9), rowheight=26)
        s.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))

    def _build_menu(self):
        mb = tk.Menu(self.root)
        self.root.config(menu=mb)

        fm = tk.Menu(mb, tearoff=0)
        mb.add_cascade(label="~File", menu=fm)
        fm.add_command(label="&Export Logs", command=self._export)
        fm.add_separator()
        fm.add_command(label="E&xit", command=self._quit_app)

        pm = tk.Menu(mb, tearoff=0)
        mb.add_cascade(label="&Policy", menu=pm)
        pm.add_command(label="Configure Patterns", command=self._config)
        pm.add_command(label="Add Pattern", command=self._add_pattern)
        pm.add_separator()
        pm.add_command(label="Reload from File", command=self._reload)
        pm.add_command(label="Sync Remote Policy", command=self._manual_sync)
        pm.add_command(label="Auto-Update Patterns", command=self._auto_update)
        pm.add_separator()
        pm.add_command(label="Test Clipboard", command=self._test_clip)
        pm.add_command(label="Pattern Sandbox", command=self._sandbox)

        tm = tk.Menu(mb, tearoff=0)
        mb.add_cascade(label="Tools", menu=tm)
        tm.add_command(label="Clipboard History", command=self._show_history)
        tm.add_command(label="Dashboard", command=self._show_dashboard)
        tm.add_command(label="Undo Last Redaction", command=self._undo_dialog)
        tm.add_separator()
        tm.add_command(label="Clear Clipboard", command=lambda: Clipboard.clear())

        sm = tk.Menu(mb, tearoff=0)
        mb.add_cascade(label="Settings", menu=sm)
        sm.add_command(label="Email Alerts", command=self._email_settings)
        sm.add_command(label="Remote Sync", command=self._sync_settings)
        sm.add_command(label="Whitelist Apps", command=self._whitelist_settings)
        sm.add_command(label="App Rules", command=self._app_rules_settings)
        sm.add_command(label="Entropy Detection", command=self._entropy_settings)
        sm.add_command(label="SIEM Integration", command=self._siem_settings)
        sm.add_command(label="Auto-Expire Clipboard", command=self._expire_settings)
        sm.add_command(label="Undo Settings", command=self._undo_settings)
        sm.add_command(label="Encryption Status", command=self._encryption_status)

    def _build_ui(self):
        sidebar = tk.Frame(self.root, bg="#0f172a", width=280)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        banner = tk.Frame(sidebar, bg="#1e293b")
        banner.pack(fill="x", padx=15, pady=(15, 8))
        banner_text = (

            "┏━┓   ╺┳╸   ┏━┓   ┏━┓      \n"
            "┗━┓    ┃    ┃ ┃   ┣━┛      \n"
            "┗━┛ ╻  ╹  ╻ ┗━┛ ╻ ╹   ╻    \n"
            "Sensitive Token Obfuscation\n"
            "& Prevention.              "
        )
        tk.Label(banner, text=banner_text, fg="#38bdf8", bg="#1e293b",
                 font=("Consolas", 9), justify="left").pack()

        tk.Label(sidebar, text=f"DLP Agent v2.0 ({SYSTEM})", fg="#94a3b8", bg="#0f172a",
                 font=("Segoe UI", 8)).pack(pady=(3, 10))

        self.btn_toggle = tk.Button(sidebar, text="▶  ENABLE", command=self._toggle,
                                    bg="#10b981", fg="white", font=("Segoe UI", 11, "bold"),
                                    relief="flat", padx=15, pady=10, cursor="hand2")
        self.btn_toggle.pack(pady=(3, 10), padx=15, fill="x")

        buttons = [
            ("⚙️ Configure", self._config, "#3b82f6"),
            ("➕ Add Pattern", self._add_pattern, "#8b5cf6"),
            ("🧪 Sandbox", self._sandbox, "#f59e0b"),
            ("📋 History", self._show_history, "#06b6d4"),
            ("📊 Dashboard", self._show_dashboard, "#6366f1"),
            ("🌐 Web Server", self._toggle_dashboard_server, "#0891b2"),
            ("↩️ Undo", self._undo_dialog, "#ef4444"),
        ]
        for text, cmd, color in buttons:
            tk.Button(sidebar, text=text, command=cmd, bg=color, fg="white",
                      font=("Segoe UI", 9), relief="flat", pady=6, cursor="hand2"
                      ).pack(pady=2, padx=15, fill="x")

        tk.Frame(sidebar, bg="#1e293b", height=1).pack(fill="x", pady=10, padx=15)

        sf = tk.Frame(sidebar, bg="#0f172a")
        sf.pack(padx=15, fill="x")

        self.stat_blocked = self._stat_row(sf, "Blocked", "0")
        self.stat_sub = self._stat_row(sf, "Substring", str(len(self.patterns.get_substring_patterns())))
        self.stat_regex = self._stat_row(sf, "Regex", str(len(self.patterns.get_regex_patterns())))
        self.stat_uptime = self._stat_row(sf, "Uptime", "00:00:00")

        tk.Frame(sidebar, bg="#1e293b", height=1).pack(fill="x", pady=8, padx=15)

        # ind = tk.Frame(sidebar, bg="#0f172a")
        # ind.pack(padx=15, fill="x")
        self.ind_frame = tk.Frame(sidebar, bg="#0f172a")
        self.ind_frame.pack(padx=15, fill="x")
        self._refresh_indicators()
        features = [
            ("Encryption", self.encryption.enabled),
            ("Email Alerts", self.config.get("email", "enabled")),
            ("Remote Sync", self.config.get("remote_sync", "enabled")),
            ("Auto-Update", self.config.get("auto_update", "enabled")),
            ("Entropy Detect", self.config.get("entropy", "enabled")),
            ("SIEM Forward", self.config.get("siem", "enabled")),
            ("Auto-Expire", self.config.get("clipboard", "auto_expire_enabled")),
            ("Undo Support", self.config.get("undo", "enabled")),
            ("Luhn Validate", True),
            ("Whitelist", self.config.get("whitelist", "enabled")),
        ]

        # Main
        main = tk.Frame(self.root, bg="#f8fafc")
        main.pack(side="right", expand=True, fill="both")

        header = tk.Frame(main, bg="#ffffff", height=60)
        header.pack(fill="x", padx=15, pady=(15, 8))
        header.pack_propagate(False)

        self.lbl_status = tk.Label(header, text="●  DISABLED", fg="#ef4444",
                                   bg="#ffffff", font=("Segoe UI", 13, "bold"))
        self.lbl_status.pack(side="left", padx=15, pady=15)

        self.lbl_hook = tk.Label(header, text="Hook: ?", fg="#64748b",
                                 bg="#ffffff", font=("Segoe UI", 9))
        self.lbl_hook.pack(side="right", padx=15)

        log_frame = tk.LabelFrame(main, text=" EVENT LOG ", bg="#ffffff", fg="#1e293b",
                                  font=("Segoe UI", 10, "bold"), relief="groove")
        log_frame.pack(expand=True, fill="both", padx=15, pady=8)

        sb = ttk.Scrollbar(log_frame, orient="vertical")
        sb.pack(side="right", fill="y")

        cols = ("time", "event", "source", "threat", "level", "score", "action")
        self.tree = ttk.Treeview(log_frame, columns=cols, show="headings", yscrollcommand=sb.set)
        sb.config(command=self.tree.yview)

        widths = {"time": 70, "event": 80, "source": 150, "threat": 250, "level": 70, "score": 50, "action": 80}
        for col, w in widths.items():
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=w, anchor="w" if col in ("source", "threat") else "center")

        self.tree.pack(expand=True, fill="both", padx=3, pady=3)

        self.tree.tag_configure("CRITICAL", background="#fee2e2")
        self.tree.tag_configure("HIGH", background="#fed7aa")
        self.tree.tag_configure("MEDIUM", background="#fef3c7")
        self.tree.tag_configure("LOW", background="#dbeafe")
        self.tree.tag_configure("INFO", background="#f3f4f6")

        bar = tk.Frame(main, bg="#1e293b", height=25)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        self.lbl_info = tk.Label(bar, text="Ready", fg="#94a3b8", bg="#1e293b", font=("Segoe UI", 8))
        self.lbl_info.pack(side="left", padx=10, pady=3)

    def _stat_row(self, p, lbl, val):
        f = tk.Frame(p, bg="#0f172a")
        f.pack(fill="x", pady=2)
        tk.Label(f, text=lbl, fg="#64748b", bg="#0f172a", font=("Segoe UI", 8)).pack(side="left")
        v = tk.Label(f, text=val, fg="#e2e8f0", bg="#0f172a", font=("Segoe UI", 9, "bold"))
        v.pack(side="right")
        return v

    def _refresh_indicators(self):
        for widget in self.ind_frame.winfo_children():
            widget.destroy()

        features = [
            ("Encryption", self.encryption.enabled),
            ("Email Alerts", self.config.get("email", "enabled")),
            ("Remote Sync", self.config.get("remote_sync", "enabled")),
            ("Auto-Update", self.config.get("auto_update", "enabled")),
            ("Entropy Detect", self.config.get("entropy", "enabled")),
            ("SIEM Forward", self.config.get("siem", "enabled")),
            ("Auto-Expire", self.config.get("clipboard", "auto_expire_enabled")),
            ("Undo Support", self.config.get("undo", "enabled")),
            ("Luhn Validate", True),
            ("Whitelist", self.config.get("whitelist", "enabled")),
        ]

        for name, enabled in features:
            row = tk.Frame(self.ind_frame, bg="#0f172a")
            row.pack(fill="x", pady=1)
            color = "#10b981" if enabled else "#ef4444"
            symbol = "[■]" if enabled else "[X]"
            tk.Label(row, text=symbol, fg=color, bg="#0f172a",
                     font=("Consolas", 7, "bold")).pack(side="left")
            tk.Label(row, text=name, fg="#64748b", bg="#0f172a",
                     font=("Segoe UI", 7)).pack(side="left", padx=3)

    def _start_timers(self):
        self._update_uptime()
        self._update_hook_status()
        # self._regex_scan_timer()

    def _update_uptime(self):
        if self.active and self.stats["start"]:
            d = datetime.datetime.now() - self.stats["start"]
            h, r = divmod(int(d.total_seconds()), 3600)
            m, s = divmod(r, 60)
            self.stat_uptime.config(text=f"{h:02d}:{m:02d}:{s:02d}")
        self.root.after(1000, self._update_uptime)

    def _update_hook_status(self):
        if self.hook.dll:
            c = self.hook.dll.GetPatternCount()
            rc = len(self.patterns.get_regex_patterns())
            self.lbl_hook.config(text=f"Hook: {c}S + {rc}R", fg="#10b981")
        else:
            self.lbl_hook.config(text="Hook: N/A", fg="#ef4444")
        self.root.after(2000, self._update_hook_status)

    def _toggle_dashboard_server(self):
        if self.dashboard.is_running():
            self.dashboard.stop()
            self.lbl_info.config(text="Dashboard server stopped")
        else:
            port = self.config.get("team_dashboard", "port", 8080)
            self.dashboard.port = port
            if self.dashboard.start():
                self.lbl_info.config(text=f"Dashboard: http://127.0.0.1:{port}")
                import webbrowser
                webbrowser.open(f"http://127.0.0.1:{port}")
            else:
                messagebox.showerror("Error", f"Cannot start on port {port}")

    # def _regex_scan_timer(self):
    #     if self.active:
    #         try:
    #             clip = Clipboard.get_text()
    #             if clip and len(clip) > 0 and len(clip) < 100000:
    #                 # Skip if clipboard was already processed by C hook
    #                 clip_hash = hashlib.sha256(clip.encode('utf-8', errors='ignore')).hexdigest()[:16]
    #
    #                 result = self.regex_scanner.scan(clip)
    #                 if result:
    #                     redacted, threats, _ = result
    #
    #                     # Store for undo before redacting
    #                     self.undo.store(clip, redacted, threats)
    #
    #                     # Small delay to avoid conflict with C hook
    #                     time.sleep(0.05)
    #
    #                     if Clipboard.set_text(redacted):
    #                         score = self.scorer.score(clip, threats, ThreatLevel.CRITICAL)
    #                         self._handle_event("THREAT", threats, score)
    #
    #                         if self.config.get("clipboard", "auto_expire_enabled"):
    #                             self._schedule_expire()
    #         except Exception as e:
    #             print(f"[REGEX SCAN ERROR] {e}")
    #
    #     self.root.after(500, self._regex_scan_timer)
    #     pass

    def _regex_scan_timer(self):
        if self.active:
            try:
                clip = Clipboard.get_text()
                if clip and 0 < len(clip) < 50000:
                    result = self.regex_scanner.scan(clip)
                    if result:
                        _, threats, _ = result
                        # DO NOT write to clipboard - causes crash
                        # Just alert the user
                        score = self.scorer.score(clip, threats, ThreatLevel.CRITICAL)
                        self._handle_event("THREAT_ALERT", threats, score)
            except:
                pass

        self.root.after(2000, self._regex_scan_timer)

    def _schedule_expire(self):
        if self._expire_timer:
            self.root.after_cancel(self._expire_timer)
        secs = self.config.get("clipboard", "auto_expire_seconds", 30) * 1000
        self._expire_timer = self.root.after(secs, self._expire_clipboard)

    def _expire_clipboard(self):
        Clipboard.clear()
        self.lbl_info.config(text="Clipboard auto-expired")

    def _on_event(self, event_type, data):
        self.root.after(0, lambda: self._handle_event(event_type, data))

 
    def _handle_event(self, event_type, data, score=0):
        if event_type in ("THREAT", "THREAT_ALERT"):
            source = Clipboard.get_window()

            if self.app_policy.is_whitelisted(source):
                return

            if not self.app_policy.should_block(source):
                return

            if score == 0:
                score = self.scorer.score(data, data, ThreatLevel.CRITICAL)

            self.stats["blocked"] += 1
            self.stat_blocked.config(text=str(self.stats["blocked"]))

            ts = datetime.datetime.now().strftime("%H:%M:%S")

            # Different label for C-blocked vs Python-detected
            action = "REDACTED" if event_type == "THREAT" else "DETECTED"
            level = "CRITICAL" if event_type == "THREAT" else "HIGH"

            self.tree.insert("", 0, values=(ts, action, source[:25], data[:45],
                                            level, f"{score:.0f}", action),
                             tags=(level,))

            event = AuditEvent(
                timestamp=datetime.datetime.now().isoformat(),
                event_type=event_type, source_app=source,
                threat=data, level=level, action=action, score=score
            )
            self.audit.log(event)
            self.siem.forward(event)

            self.clip_history.add(data, source, True, data)

            self.emailer.send_alert(data, source, ts, score)

            self._toast(data, score)
            self.lbl_info.config(text=f"{action}: {data[:40]} (Score: {score:.0f})")



    def _toast(self, message, score=0):
        toast = tk.Toplevel(self.root)
        toast.overrideredirect(True)
        toast.attributes("-topmost", True)
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        toast.geometry(f"420x80+{sw - 440}+{sh - 140}")
        color = "#dc2626" if score >= 70 else "#ea580c" if score >= 50 else "#f59e0b"
        toast.configure(bg=color)
        tk.Label(toast, text=f"🚨 SENSITIVE DATA DETECTED (Score: {score:.0f}/100)",
                 fg="white", bg=color, font=("Segoe UI", 11, "bold")).pack(pady=(12, 4))
        tk.Label(toast, text=message[:50], fg="white", bg=color,
                 font=("Segoe UI", 9)).pack()
        self.root.after(3500, toast.destroy)

    def _toggle(self):
        self.active = not self.active
        self.hook.set_active(self.active)
        if self.active:
            self.btn_toggle.config(text="⏸  DISABLE", bg="#ef4444")
            self.lbl_status.config(text="●  ACTIVE", fg="#10b981")
            self.stats["start"] = datetime.datetime.now()
            self.lbl_info.config(text="Monitoring (substring + regex + entropy + luhn)...")
            self.audit.log(AuditEvent(timestamp=datetime.datetime.now().isoformat(),
                                      event_type="SYSTEM", source_app="STOP Sentinel",
                                      threat="N/A", level="INFO", action="ENABLED"))
        else:
            self.btn_toggle.config(text="▶  ENABLE", bg="#10b981")
            self.lbl_status.config(text="●  DISABLED", fg="#ef4444")
            self.lbl_info.config(text="Paused")
            self.audit.log(AuditEvent(timestamp=datetime.datetime.now().isoformat(),
                                      event_type="SYSTEM", source_app="STOP Sentinel",
                                      threat="N/A", level="INFO", action="DISABLED"))

    def _reload(self):
        self.patterns.reload()
        count = self.hook.load_patterns(self.patterns.get_enabled())
        self.stat_sub.config(text=str(len(self.patterns.get_substring_patterns())))
        self.stat_regex.config(text=str(len(self.patterns.get_regex_patterns())))
        messagebox.showinfo("Reload", f"Loaded {count} patterns (all types)")

    def _manual_sync(self):
        err = self.remote_sync.sync_policy()
        if err:
            messagebox.showerror("Sync", err)
        else:
            self._reload()

    def _auto_update(self):
        err = self.remote_sync.auto_update_patterns()
        if err:
            messagebox.showerror("Update", err)
        else:
            self._reload()

    def _test_clip(self):
        clip = Clipboard.get_text()
        if not clip:
            messagebox.showinfo("Test", "Empty")
            return
        found = []
        for p in self.patterns.get_substring_patterns():
            if p.pattern.lower() in clip.lower():
                found.append(f"{p.name} (sub)")
        for p in self.patterns.get_regex_patterns():
            try:
                if re.search(p.pattern, clip, re.IGNORECASE):
                    found.append(f"{p.name} (regex)")
            except:
                pass
        cards = self.luhn.extract_and_validate(clip)
        if cards:
            found.append(f"Credit Card (Luhn): {len(cards)} found")
        high_ent = self.entropy_detector.find_high_entropy(clip)
        if high_ent:
            found.append(f"High Entropy: {len(high_ent)} strings")
        if found:
            messagebox.showwarning("Test", "\n".join(found))
        else:
            messagebox.showinfo("Test", "No threats")

    def _sandbox(self):
        win = tk.Toplevel(self.root)
        win.title("Pattern Testing Sandbox")
        win.geometry("700x500")
        win.configure(bg="#f8fafc")
        win.transient(self.root)

        tk.Label(win, text="Pattern Testing Sandbox", bg="#1e293b", fg="white",
                 font=("Segoe UI", 12, "bold")).pack(fill="x", ipady=12)

        form = tk.Frame(win, bg="#ffffff")
        form.pack(expand=True, fill="both", padx=15, pady=15)

        tk.Label(form, text="Paste text to test:", bg="#ffffff",
                 font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(10, 5))

        text_area = tk.Text(form, height=10, font=("Consolas", 10), wrap="word")
        text_area.pack(fill="both", expand=True, pady=(0, 10))

        result_area = tk.Text(form, height=8, font=("Consolas", 9), wrap="word",
                              bg="#f1f5f9", state="disabled")
        result_area.pack(fill="both", expand=True)

        def test():
            content = text_area.get("1.0", "end").strip()
            if not content:
                return

            results = []

            # Substring
            for p in self.patterns.get_substring_patterns():
                if p.pattern.lower() in content.lower():
                    results.append(f"[SUBSTRING] {p.name} - matched '{p.pattern}'")

            # Regex
            for p in self.patterns.get_regex_patterns():
                try:
                    matches = re.findall(p.pattern, content, re.IGNORECASE)
                    if matches:
                        results.append(f"[REGEX] {p.name} - {len(matches)} match(es)")
                except:
                    pass

            # Luhn
            cards = self.luhn.extract_and_validate(content)
            for card in cards:
                results.append(f"[LUHN] Valid credit card: {card[:4]}...{card[-4:]}")

            # Entropy
            high_ent = self.entropy_detector.find_high_entropy(content)
            for word, ent in high_ent:
                results.append(f"[ENTROPY] High entropy ({ent}): {word[:30]}...")

            # Score
            if results:
                score = self.scorer.score(content, "test", ThreatLevel.HIGH)
                results.append(f"\nThreat Score: {score:.0f}/100")
            else:
                results.append("No threats detected")

            result_area.config(state="normal")
            result_area.delete("1.0", "end")
            result_area.insert("1.0", "\n".join(results))
            result_area.config(state="disabled")

        tk.Button(form, text="Test", command=test, bg="#f59e0b", fg="white",
                  font=("Segoe UI", 10, "bold"), relief="flat", padx=20, pady=6).pack(pady=10)

    def _show_history(self):
        win = tk.Toplevel(self.root)
        win.title("Clipboard History")
        win.geometry("900x650")
        win.configure(bg="#f8fafc")
        win.transient(self.root)

        tk.Label(win, text="Clipboard History (Encrypted)", bg="#1e293b", fg="white",
                 font=("Segoe UI", 12, "bold")).pack(fill="x", ipady=12)

        container = tk.Frame(win, bg="#ffffff")
        container.pack(expand=True, fill="both", padx=15, pady=15)

        scrollbar = ttk.Scrollbar(container, orient="vertical")
        scrollbar.pack(side="right", fill="y")

        cols = ("time", "source", "preview", "threat", "threat_name")
        tree = ttk.Treeview(win, columns=cols, show="headings",
                            yscrollcommand=scrollbar.set)
        scrollbar.config(command=tree.yview)

        tree.heading("time", text="TIME")
        tree.heading("source", text="SOURCE")
        tree.heading("preview", text="PREVIEW")
        tree.heading("threat", text="THREAT?")
        tree.heading("threat_name", text="THREAT NAME")

        tree.column("time", width=150)
        tree.column("source", width=150)
        tree.column("preview", width=300)
        tree.column("threat", width=80)
        tree.column("threat_name", width=150)

        for entry in self.clip_history.get_entries():
            tag = "CRITICAL" if entry["threat"] else "INFO"
            tree.insert("", "end", values=(
                entry["timestamp"][:19],
                entry["source"][:25],
                entry["preview"][:50],
                "YES" if entry["threat"] else "No",
                entry.get("threat_name", "")[:30]
            ), tags=(tag,))

        tree.tag_configure("CRITICAL", background="#fee2e2")
        tree.tag_configure("INFO", background="#f3f4f6")
        tree.pack(expand=True, fill="both", padx=15, pady=(0, 10))

        btn_frame = tk.Frame(win, bg="#f8fafc")
        btn_frame.pack(fill="x", padx=15, pady=(0, 15))

        tk.Button(btn_frame, text="Clear History",
                  command=lambda: (self.clip_history.clear(), win.destroy()),
                  bg="#ef4444", fg="white", font=("Segoe UI", 10),
                  relief="flat", padx=15, pady=6).pack(side="right")

        tk.Label(btn_frame, text=f"Total entries: {len(self.clip_history.entries)}",
                 bg="#f8fafc", fg="#64748b", font=("Segoe UI", 9)).pack(side="left")

    def _show_dashboard(self):
        win = tk.Toplevel(self.root)
        win.title("Security Dashboard")
        win.geometry("600x500")
        win.configure(bg="#f8fafc")
        win.transient(self.root)

        tk.Label(win, text="Security Dashboard", bg="#1e293b", fg="white",
                 font=("Segoe UI", 12, "bold")).pack(fill="x", ipady=12)

        stats = self.audit.get_stats()

        info = tk.Frame(win, bg="#ffffff")
        info.pack(fill="both", expand=True, padx=15, pady=15)

        metrics = [
            ("Total Events", str(stats["total_events"])),
            ("Today's Events", str(stats["today_events"])),
            ("Threats Today", str(stats["threats_today"])),
        ]

        for label, value in metrics:
            row = tk.Frame(info, bg="#ffffff")
            row.pack(fill="x", pady=5, padx=20)
            tk.Label(row, text=label, bg="#ffffff", font=("Segoe UI", 11)).pack(side="left")
            tk.Label(row, text=value, bg="#ffffff", font=("Segoe UI", 11, "bold"),
                     fg="#dc2626" if "Threat" in label else "#1e293b").pack(side="right")

        if stats["by_level"]:
            tk.Label(info, text="\nBy Severity:", bg="#ffffff",
                     font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=20)
            for level, count in stats["by_level"].items():
                tk.Label(info, text=f"  {level}: {count}", bg="#ffffff",
                         font=("Segoe UI", 10)).pack(anchor="w", padx=20)

        if stats["by_threat"]:
            tk.Label(info, text="\nTop Threats:", bg="#ffffff",
                     font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=20)
            for threat, count in sorted(stats["by_threat"].items(), key=lambda x: -x[1])[:10]:
                tk.Label(info, text=f"  {threat}: {count}", bg="#ffffff",
                         font=("Segoe UI", 10)).pack(anchor="w", padx=20)

        if stats["by_source"]:
            tk.Label(info, text="\nTop Sources:", bg="#ffffff",
                     font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=20)
            for src, count in sorted(stats["by_source"].items(), key=lambda x: -x[1])[:5]:
                tk.Label(info, text=f"  {src}: {count}", bg="#ffffff",
                         font=("Segoe UI", 10)).pack(anchor="w", padx=20)

    def _undo_dialog(self):
        recent = self.undo.get_recent()
        if not recent:
            messagebox.showinfo("Undo", "No redactions to undo")
            return

        win = tk.Toplevel(self.root)
        win.title("Undo Redaction")
        win.geometry("500x300")
        win.configure(bg="#f8fafc")
        win.transient(self.root)
        win.grab_set()

        tk.Label(win, text="Undo Redaction (PIN Required)", bg="#1e293b", fg="white",
                 font=("Segoe UI", 12, "bold")).pack(fill="x", ipady=12)

        form = tk.Frame(win, bg="#ffffff")
        form.pack(expand=True, fill="both", padx=15, pady=15)

        tk.Label(form, text="Recent redactions:", bg="#ffffff",
                 font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(10, 5))

        for i, entry in enumerate(recent[:5]):
            tk.Label(form, text=f"{i + 1}. [{entry['timestamp'][:19]}] {entry['threat'][:40]}",
                     bg="#ffffff", font=("Consolas", 9)).pack(anchor="w", padx=10)

        tk.Label(form, text="\nEnter PIN:", bg="#ffffff",
                 font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(15, 5))
        pin_entry = tk.Entry(form, show="*", font=("Segoe UI", 12), width=10)
        pin_entry.pack(anchor="w", padx=10)

        def undo():
            pin = pin_entry.get()
            original = self.undo.retrieve(pin, 0)
            if original:
                Clipboard.set_text(original)
                win.destroy()
                messagebox.showinfo("Undo", "Original content restored to clipboard")
            else:
                messagebox.showerror("Error", "Invalid PIN or expired", parent=win)

        tk.Button(form, text="Restore to Clipboard", command=undo, bg="#ef4444", fg="white",
                  font=("Segoe UI", 10, "bold"), relief="flat", padx=20, pady=6).pack(pady=15)



    def _config(self):
        win = tk.Toplevel(self.root)
        win.title("Patterns")
        win.geometry("750x550")
        win.configure(bg="#f8fafc")
        win.transient(self.root)
        win.grab_set()

        tk.Label(win, text="Detection Patterns", bg="#1e293b", fg="white",
                 font=("Segoe UI", 12, "bold")).pack(fill="x", ipady=12)

        container = tk.Frame(win, bg="#ffffff")
        container.pack(expand=True, fill="both", padx=10, pady=10)

        canvas = tk.Canvas(container, bg="#ffffff", highlightthickness=0)
        sb = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        sf = tk.Frame(canvas, bg="#ffffff")
        sf.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=sf, anchor="nw", width=710)
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1 * (e.delta / 120)), "units"))

        # Group patterns by category
        category_keywords = {
            "🔐 Authentication & Tokens": ["github", "aws", "gcp", "azure", "slack", "stripe",
                                          "sendgrid", "npm", "pypi", "jwt", "bearer", "token",
                                          "oauth", "heroku", "password_assignment", "secret_assignment",
                                          "api_key_assignment"],
            "🔑 Private Keys & Certificates": ["key", "rsa", "openssh", "ec_", "pgp", "pem",
                                              "private"],
            "🗄️ Database Credentials": ["postgresql", "mysql", "mongodb", "redis", "database"],
            "💳 Financial & PII": ["visa", "mastercard", "amex", "american", "discover", "card",
                                  "ssn", "aadhaar", "pan_", "iban", "sin", "tfn", "cpf", "nir",
                                  "passport", "phone", "email", "ni_number", "germany"],
            "📁 File Paths & Config": ["ssh_config", "env_file", "kube", "docker", "htpasswd",
                                      "shadow", "pem_file", "key_file"],
            "🌐 URL Parameters": ["url_", "access_token", "refresh_token"],
        }

        categories = {}
        for cat in category_keywords:
            categories[cat] = []
        categories["⚡ Other"] = []

        for key in sorted(self.patterns.patterns.keys()):
            p = self.patterns.patterns[key]
            placed = False
            key_lower = key.lower()

            for cat, keywords in category_keywords.items():
                for kw in keywords:
                    if kw in key_lower:
                        categories[cat].append((key, p))
                        placed = True
                        break
                if placed:
                    break

            if not placed:
                categories["⚡ Other"].append((key, p))

        pvars = {}
        row_idx = 0

        for cat_name, patterns in categories.items():
            if not patterns:
                continue

            enabled_count = sum(1 for _, p in patterns if p.enabled)
            total_count = len(patterns)

            # Container for this entire category (header + items)
            cat_container = tk.Frame(sf, bg="#ffffff")
            cat_container.pack(fill="x", padx=5, pady=(6, 0))

            # Items frame - always exists, visibility toggled via height
            items_frame = tk.Frame(cat_container, bg="#ffffff")

            # Build items first
            for key, p in patterns:
                var = tk.BooleanVar(value=p.enabled)
                pvars[key] = var

                row = tk.Frame(items_frame, bg="#ffffff", relief="solid", bd=1)
                row.pack(fill="x", padx=10, pady=1)

                inner = tk.Frame(row, bg="#ffffff")
                inner.pack(fill="x", padx=6, pady=4)

                tk.Checkbutton(inner, text=p.name, variable=var, bg="#ffffff",
                               font=("Segoe UI", 9)).pack(side="left")

                # Delete button
                def make_delete(k=key, w=win):
                    def do_delete():
                        if messagebox.askyesno("Delete", f"Delete '{self.patterns.patterns[k].name}'?", parent=w):
                            self.patterns.patterns.pop(k, None)
                            self.patterns.save_to_file()
                            w.destroy()
                            self._config()  # Reopen
                    return do_delete

                tk.Button(inner, text="✕", command=make_delete(), bg="#ef4444", fg="white",
                          font=("Segoe UI", 7, "bold"), relief="flat", padx=4, pady=0,
                          cursor="hand2").pack(side="right", padx=2)

                # Edit button
                def make_edit(k=key, w=win):
                    def do_edit():
                        self._edit_pattern(k, w)
                    return do_edit

                tk.Button(inner, text="✎", command=make_edit(), bg="#f59e0b", fg="white",
                          font=("Segoe UI", 7, "bold"), relief="flat", padx=4, pady=0,
                          cursor="hand2").pack(side="right", padx=2)

                # Type badge
                tc = "#8b5cf6" if p.pattern_type == "regex" else "#06b6d4"
                tk.Label(inner, text=p.pattern_type.upper(), bg=tc, fg="white",
                         font=("Segoe UI", 6, "bold"), padx=3).pack(side="right", padx=2)

                # Level badge
                tk.Label(inner, text=p.threat_level.name, bg=p.threat_level.value, fg="white",
                         font=("Segoe UI", 6, "bold"), padx=4).pack(side="right")

                # Pattern text
                tk.Label(row, text=p.pattern[:60], bg="#ffffff", fg="#94a3b8",
                         font=("Consolas", 7)).pack(anchor="w", padx=30, pady=(0, 3))
            # Start expanded
            items_frame.pack(fill="x", pady=(0, 5))

            # Header with toggle
            cat_header = tk.Frame(cat_container, bg="#e2e8f0")
            cat_header.pack(fill="x", before=items_frame)

            # State tracker
            is_expanded = [True]

            def make_toggle(frame, expanded_state, btn_ref):
                def toggle():
                    if expanded_state[0]:
                        frame.pack_forget()
                        expanded_state[0] = False
                        btn_ref[0].config(text="▶")
                    else:
                        # Re-pack AFTER the header, INSIDE the same container
                        frame.pack(fill="x", pady=(0, 5))
                        expanded_state[0] = True
                        btn_ref[0].config(text="▼")

                return toggle

            btn_holder = [None]

            toggle_btn = tk.Button(cat_header, text="▼",
                                   bg="#e2e8f0", fg="#1e293b", font=("Consolas", 10, "bold"),
                                   relief="flat", width=2, cursor="hand2")
            btn_holder[0] = toggle_btn
            toggle_btn.config(command=make_toggle(items_frame, is_expanded, btn_holder))
            toggle_btn.pack(side="left", padx=5)

            tk.Label(cat_header, text=f"{cat_name} ({enabled_count}/{total_count})",
                     bg="#e2e8f0", fg="#1e293b", font=("Segoe UI", 10, "bold")).pack(side="left", padx=5)

            def make_select(cat_patterns, select):
                def do_it():
                    for k, _ in cat_patterns:
                        if k in pvars:
                            pvars[k].set(select)

                return do_it

            tk.Button(cat_header, text="All", command=make_select(patterns, True),
                      bg="#10b981", fg="white", font=("Segoe UI", 7, "bold"),
                      relief="flat", padx=4, cursor="hand2").pack(side="right", padx=2)
            tk.Button(cat_header, text="None", command=make_select(patterns, False),
                      bg="#ef4444", fg="white", font=("Segoe UI", 7, "bold"),
                      relief="flat", padx=4, cursor="hand2").pack(side="right", padx=2)

        # Bottom buttons
        bf = tk.Frame(win, bg="#f8fafc")
        bf.pack(fill="x", padx=10, pady=8)

        def save():
            for k, v in pvars.items():
                self.patterns.set_enabled(k, v.get())
            self.patterns.save_to_file()
            self.hook.load_patterns(self.patterns.get_enabled())
            self.stat_sub.config(text=str(len(self.patterns.get_substring_patterns())))
            self.stat_regex.config(text=str(len(self.patterns.get_regex_patterns())))
            canvas.unbind_all("<MouseWheel>")
            win.grab_release()
            self._refresh_indicators()
            win.destroy()

        def select_all():
            for v in pvars.values():
                v.set(True)

        def select_none():
            for v in pvars.values():
                v.set(False)

        tk.Button(bf, text="Enable All", command=select_all, bg="#10b981", fg="white",
                  font=("Segoe UI", 9), relief="flat", padx=12, pady=5).pack(side="left")
        tk.Button(bf, text="Disable All", command=select_none, bg="#ef4444", fg="white",
                  font=("Segoe UI", 9), relief="flat", padx=12, pady=5).pack(side="left", padx=5)

        tk.Button(bf, text="Save", command=save, bg="#10b981", fg="white",
                  font=("Segoe UI", 10, "bold"), relief="flat", padx=20, pady=5).pack(side="right")
        tk.Button(bf, text="Cancel", command=lambda: (canvas.unbind_all("<MouseWheel>"), win.destroy()),
                  bg="#64748b", fg="white", relief="flat", padx=20, pady=5).pack(side="right", padx=8)

    def _add_pattern(self):
        win = tk.Toplevel(self.root)
        win.title("Add Pattern")
        win.geometry("500x380")
        win.configure(bg="#f8fafc")
        win.transient(self.root)
        win.grab_set()

        tk.Label(win, text="Add Pattern", bg="#1e293b", fg="white",
                 font=("Segoe UI", 12, "bold")).pack(fill="x", ipady=12)

        form = tk.Frame(win, bg="#ffffff")
        form.pack(expand=True, fill="both", padx=15, pady=15)

        for label in ["Name:", "Pattern:", "Description:"]:
            tk.Label(form, text=label, bg="#ffffff", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(8, 2))
            e = tk.Entry(form, font=("Consolas" if "Pattern" in label else "Segoe UI", 10), width=45)
            e.pack(fill="x")
            if label == "Name:":
                en = e
            elif label == "Pattern:":
                ep = e
            else:
                ed = e

        tk.Label(form, text="Type:", bg="#ffffff", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(8, 2))
        pt = tk.StringVar(value="substring")
        tf = tk.Frame(form, bg="#ffffff")
        tf.pack(fill="x")
        tk.Radiobutton(tf, text="Substring", variable=pt, value="substring", bg="#ffffff").pack(side="left", padx=5)
        tk.Radiobutton(tf, text="Regex", variable=pt, value="regex", bg="#ffffff").pack(side="left", padx=5)

        tk.Label(form, text="Level:", bg="#ffffff", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(8, 2))
        lv = tk.StringVar(value="HIGH")
        lf = tk.Frame(form, bg="#ffffff")
        lf.pack(fill="x")
        for l in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            tk.Radiobutton(lf, text=l, variable=lv, value=l, bg="#ffffff").pack(side="left", padx=5)

        def add():
            n, p, d = en.get().strip(), ep.get().strip(), ed.get().strip()
            if not n or not p:
                messagebox.showerror("Error", "Required", parent=win)
                return
            if pt.get() == "regex":
                try:
                    re.compile(p)
                except re.error as e:
                    messagebox.showerror("Error", f"Invalid regex: {e}", parent=win)
                    return
            self.patterns.add_pattern(n, p, ThreatLevel[lv.get()], d or n, pt.get())
            self.hook.load_patterns(self.patterns.get_substring_patterns())
            self.stat_sub.config(text=str(len(self.patterns.get_substring_patterns())))
            self.stat_regex.config(text=str(len(self.patterns.get_regex_patterns())))
            win.destroy()

        tk.Button(form, text="Add", command=add, bg="#10b981", fg="white",
                  font=("Segoe UI", 10, "bold"), relief="flat", padx=20, pady=6).pack(pady=10)

    def _edit_pattern(self, key, parent_win):
        if key not in self.patterns.patterns:
            return

        p = self.patterns.patterns[key]

        win = tk.Toplevel(self.root)
        win.title(f"Edit: {p.name}")
        win.geometry("500x480")
        win.configure(bg="#f8fafc")
        win.transient(self.root)
        win.grab_set()

        tk.Label(win, text=f"Edit Pattern", bg="#1e293b", fg="white",
                 font=("Segoe UI", 12, "bold")).pack(fill="x", ipady=12)

        form = tk.Frame(win, bg="#ffffff")
        form.pack(expand=True, fill="both", padx=15, pady=15)

        # Name
        tk.Label(form, text="Name:", bg="#ffffff", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(10, 3))
        en = tk.Entry(form, font=("Segoe UI", 10), width=45)
        en.insert(0, p.name)
        en.pack(fill="x")

        # Pattern
        tk.Label(form, text="Pattern:", bg="#ffffff", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(10, 3))
        ep = tk.Entry(form, font=("Consolas", 10), width=45)
        ep.insert(0, p.pattern)
        ep.pack(fill="x")

        # Description
        tk.Label(form, text="Description:", bg="#ffffff", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(10, 3))
        ed = tk.Entry(form, font=("Segoe UI", 10), width=45)
        ed.insert(0, p.description)
        ed.pack(fill="x")

        # Type
        tk.Label(form, text="Type:", bg="#ffffff", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(8, 2))
        pt = tk.StringVar(value=p.pattern_type)
        tf = tk.Frame(form, bg="#ffffff")
        tf.pack(fill="x")
        tk.Radiobutton(tf, text="Substring", variable=pt, value="substring", bg="#ffffff").pack(side="left", padx=5)
        tk.Radiobutton(tf, text="Regex", variable=pt, value="regex", bg="#ffffff").pack(side="left", padx=5)

        # Threat Level
        tk.Label(form, text="Level:", bg="#ffffff", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(8, 2))
        lv = tk.StringVar(value=p.threat_level.name)
        lf = tk.Frame(form, bg="#ffffff")
        lf.pack(fill="x")
        for l in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            tk.Radiobutton(lf, text=l, variable=lv, value=l, bg="#ffffff").pack(side="left", padx=5)

        # Buttons
        bf = tk.Frame(win, bg="#f8fafc")
        bf.pack(fill="x", padx=15, pady=15)

        def save_edit():
            name = en.get().strip()
            pattern = ep.get().strip()
            desc = ed.get().strip()

            if not name or not pattern:
                messagebox.showerror("Error", "Name and pattern required", parent=win)
                return

            if pt.get() == "regex":
                try:
                    import re
                    re.compile(pattern)
                except re.error as e:
                    messagebox.showerror("Error", f"Invalid regex: {e}", parent=win)
                    return

            # Remove old key, add new
            old_pattern = self.patterns.patterns.pop(key, None)
            new_key = name.upper().replace(' ', '_').replace('-', '_')

            self.patterns.patterns[new_key] = SecurityPattern(
                name=name,
                pattern=pattern,
                threat_level=ThreatLevel[lv.get()],
                description=desc or name,
                enabled=old_pattern.enabled if old_pattern else True,
                is_builtin=False,
                pattern_type=pt.get()
            )

            self.patterns.save_to_file()
            self.hook.load_patterns(self.patterns.get_substring_patterns())
            self.stat_sub.config(text=str(len(self.patterns.get_substring_patterns())))
            self.stat_regex.config(text=str(len(self.patterns.get_regex_patterns())))

            win.destroy()
            parent_win.destroy()
            self._config()  # Reopen config with updated data

        tk.Button(bf, text="Save", command=save_edit, bg="#10b981", fg="white",
                  font=("Segoe UI", 10, "bold"), relief="flat", padx=20, pady=6).pack(side="right")
        tk.Button(bf, text="Cancel", command=win.destroy, bg="#64748b", fg="white",
                  font=("Segoe UI", 10), relief="flat", padx=20, pady=6).pack(side="right", padx=10)

    # ================================
    # SETTINGS DIALOGS
    # ================================
    def _settings_dialog(self, title, section, fields):
        win = tk.Toplevel(self.root)
        win.title(title)
        win.geometry("450x" + str(120 + len(fields) * 50))
        win.configure(bg="#f8fafc")
        win.transient(self.root)
        win.grab_set()

        tk.Label(win, text=title, bg="#1e293b", fg="white",
                 font=("Segoe UI", 12, "bold")).pack(fill="x", ipady=12)

        form = tk.Frame(win, bg="#ffffff")
        form.pack(expand=True, fill="both", padx=15, pady=15)

        entries = {}
        for label, key, ftype in fields:
            if ftype == "bool":
                var = tk.BooleanVar(value=self.config.get(section, key, False))
                tk.Checkbutton(form, text=label, variable=var, bg="#ffffff",
                               font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=5)
                entries[key] = ("bool", var)
            else:
                tk.Label(form, text=label, bg="#ffffff", font=("Segoe UI", 9)).pack(anchor="w", pady=(5, 2))
                e = tk.Entry(form, font=("Segoe UI", 9), width=45,
                             show="*" if "password" in key or "pin" in key else "")
                e.insert(0, str(self.config.get(section, key, "")))
                e.pack(fill="x")
                entries[key] = ("str", e)

        def save():
            for key, (ftype, widget) in entries.items():
                if ftype == "bool":
                    self.config.set(section, key, widget.get())
                else:
                    val = widget.get().strip()
                    if key in ("smtp_port", "port", "interval_minutes", "check_interval_hours",
                               "auto_expire_seconds", "expire_seconds", "threshold", "min_length"):
                        try:
                            val = float(val) if "." in val else int(val)
                        except:
                            pass
                    self.config.set(section, key, val)
            self.config.save()
            self._refresh_indicators()
            win.destroy()

        tk.Button(form, text="Save", command=save, bg="#10b981", fg="white",
                  font=("Segoe UI", 10, "bold"), relief="flat", padx=20, pady=6).pack(pady=10)

    def _email_settings(self):
        self._settings_dialog("Email Alerts", "email", [
            ("Enable Email Alerts", "enabled", "bool"),
            ("SMTP Server:", "smtp_server", "str"),
            ("SMTP Port:", "smtp_port", "str"),
            ("Username:", "username", "str"),
            ("Password:", "password", "str"),
            ("From:", "from_addr", "str"),
            ("To:", "to_addrs", "str"),
        ])

    def _sync_settings(self):
        self._settings_dialog("Remote Sync", "remote_sync", [
            ("Enable Sync", "enabled", "bool"),
            ("Policy URL:", "url", "str"),
            ("Auth Token:", "auth_token", "str"),
            ("Interval (min):", "interval_minutes", "str"),
        ])

    def _whitelist_settings(self):
        win = tk.Toplevel(self.root)
        win.title("Whitelist Applications")
        win.geometry("400x400")
        win.configure(bg="#f8fafc")
        win.transient(self.root)
        win.grab_set()

        tk.Label(win, text="Whitelisted Apps (skip scanning)", bg="#1e293b", fg="white",
                 font=("Segoe UI", 12, "bold")).pack(fill="x", ipady=12)

        form = tk.Frame(win, bg="#ffffff")
        form.pack(expand=True, fill="both", padx=15, pady=15)

        enabled_var = tk.BooleanVar(value=self.config.get("whitelist", "enabled", True))
        tk.Checkbutton(form, text="Enable Whitelist", variable=enabled_var, bg="#ffffff",
                       font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=10)

        tk.Label(form, text="Apps (one per line):", bg="#ffffff", font=("Segoe UI", 9)).pack(anchor="w")
        text_area = tk.Text(form, height=8, font=("Segoe UI", 9))
        apps = self.config.get("whitelist", "apps", [])
        text_area.insert("1.0", "\n".join(apps))
        text_area.pack(fill="both", expand=True, pady=5)

        def save():
            self.config.set("whitelist", "enabled", enabled_var.get())
            app_list = [a.strip() for a in text_area.get("1.0", "end").strip().split("\n") if a.strip()]
            self.config.set("whitelist", "apps", app_list)
            self.config.save()
            self._refresh_indicators()
            win.destroy()

        tk.Button(form, text="Save", command=save, bg="#10b981", fg="white",
                  font=("Segoe UI", 10, "bold"), relief="flat", padx=20, pady=6).pack(pady=10)

    def _app_rules_settings(self):
        win = tk.Toplevel(self.root)
        win.title("Application Rules")
        win.geometry("500x440")
        win.configure(bg="#f8fafc")
        win.transient(self.root)
        win.grab_set()

        tk.Label(win, text="Per-Application Rules", bg="#1e293b", fg="white",
                 font=("Segoe UI", 12, "bold")).pack(fill="x", ipady=12)

        form = tk.Frame(win, bg="#ffffff")
        form.pack(expand=True, fill="both", padx=15, pady=15)

        tk.Label(form, text="Rules JSON (app: {block, alert, level}):", bg="#ffffff",
                 font=("Segoe UI", 9)).pack(anchor="w", pady=5)
        text_area = tk.Text(form, height=12, font=("Consolas", 9))
        rules = self.config.get("app_rules", default={})
        text_area.insert("1.0", json.dumps(rules, indent=2))
        text_area.pack(fill="both", expand=True, pady=5)

        def save():
            try:
                parsed = json.loads(text_area.get("1.0", "end"))
                self.config.config["app_rules"] = parsed
                self.config.save()
                self._refresh_indicators()
                win.destroy()

            except json.JSONDecodeError as e:
                messagebox.showerror("Error", f"Invalid JSON: {e}", parent=win)

        tk.Button(form, text="Save", command=save, bg="#10b981", fg="white",
                  font=("Segoe UI", 10, "bold"), relief="flat", padx=20, pady=6).pack(pady=10)

    def _entropy_settings(self):
        self._settings_dialog("Entropy Detection", "entropy", [
            ("Enable Entropy Detection", "enabled", "bool"),
            ("Threshold (default 4.5):", "threshold", "str"),
            ("Min String Length:", "min_length", "str"),
        ])

    def _siem_settings(self):
        self._settings_dialog("SIEM Integration", "siem", [
            ("Enable SIEM Forwarding", "enabled", "bool"),
            ("Host:", "host", "str"),
            ("Port:", "port", "str"),
            ("Protocol (UDP/TCP):", "protocol", "str"),
            ("Format (CEF/syslog):", "format", "str"),
        ])

    def _expire_settings(self):
        self._settings_dialog("Auto-Expire Clipboard", "clipboard", [
            ("Enable Auto-Expire", "auto_expire_enabled", "bool"),
            ("Seconds After Threat:", "auto_expire_seconds", "str"),
        ])

    def _undo_settings(self):
        self._settings_dialog("Undo Settings", "undo", [
            ("Enable Undo", "enabled", "bool"),
            ("PIN Code:", "pin", "str"),
            ("Expire Seconds:", "expire_seconds", "str"),
        ])

    def _encryption_status(self):
        messagebox.showinfo("Encryption",
                            f"Status: {'ON' if self.encryption.enabled else 'OFF'}\n"
                            f"Algorithm: Fernet (AES-128-CBC)\n"
                            f"Key: {KEY_FILE}\n"
                            f"Logs: {LOGS_DIR}")

    def _export(self):
        f = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if f:
            if self.audit.export(f):
                messagebox.showinfo("Export", f"Saved to {f}")
            else:
                messagebox.showwarning("Export", "No data")


def main():
    if SYSTEM == "Windows":
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID('stop.sentinel.dlp')
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except:
            pass

    root = tk.Tk()
    try:
        if SYSTEM == "Windows":
            icon = APP_DIR / "icon.ico"
            if icon.exists():
                root.iconbitmap(str(icon))
        else:
            icon = APP_DIR / "icon.png"
            if icon.exists():
                img = tk.PhotoImage(file=str(icon))
                root.iconphoto(True, img)
    except:
        pass

    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
