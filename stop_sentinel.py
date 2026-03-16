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
import ctypes.util
import threading
import datetime
import json
import csv
import time
import platform
import subprocess
import os
from pathlib import Path
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, asdict
from enum import Enum

SYSTEM = platform.system()  # "Windows", "Linux", "Darwin"
APP_DIR = Path(__file__).parent
HOOKS_FILE = APP_DIR / "hooks.dlp"
LOGS_DIR = APP_DIR / "stop_sentinel_logs"
LOGS_DIR.mkdir(exist_ok=True)

if SYSTEM == "Windows":
    DLL_PATH = APP_DIR / "promptsec_hook.dll"
elif SYSTEM == "Darwin":
    DLL_PATH = APP_DIR / "stop_sentinel_hook.dylib"
else:
    DLL_PATH = APP_DIR / "stop_sentinel_hook.so"


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


@dataclass
class AuditEvent:
    timestamp: str
    event_type: str
    source_app: str
    threat: str
    level: str
    action: str


class AuditLogger:
    def __init__(self):
        LOGS_DIR.mkdir(exist_ok=True)

    def log(self, event: AuditEvent):
        path = LOGS_DIR / f"audit_{datetime.date.today()}.jsonl"
        try:
            with open(path, 'a', encoding='utf-8') as f:
                json.dump(asdict(event), f)
                f.write('\n')
        except Exception as e:
            print(f"[LOG ERROR] {e}")

    def export(self, output: str) -> bool:
        try:
            events = []
            for f in LOGS_DIR.glob("audit_*.jsonl"):
                with open(f, 'r', encoding='utf-8') as file:
                    for line in file:
                        if line.strip():
                            events.append(json.loads(line))
            if events:
                with open(output, 'w', newline='', encoding='utf-8') as f:
                    w = csv.DictWriter(f, fieldnames=events[0].keys())
                    w.writeheader()
                    w.writerows(events)
                return True
        except Exception as e:
            print(f"[EXPORT ERROR] {e}")
        return False


class Clipboard:
    """Cross-platform clipboard operations"""

    @staticmethod
    def get_text() -> Optional[str]:
        if SYSTEM == "Windows":
            return Clipboard._get_windows()
        elif SYSTEM == "Darwin":
            return Clipboard._get_macos()
        else:
            return Clipboard._get_linux()

    @staticmethod
    def _get_windows() -> Optional[str]:
        try:
            import ctypes
            from ctypes import wintypes

            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32

            if not user32.OpenClipboard(None):
                return None
            try:
                h = user32.GetClipboardData(13)  # CF_UNICODETEXT
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
    def _get_macos() -> Optional[str]:
        try:
            result = subprocess.run(
                ['pbpaste'],
                capture_output=True, text=True, timeout=2
            )
            return result.stdout if result.returncode == 0 else None
        except:
            return None

    @staticmethod
    def _get_linux() -> Optional[str]:
        for cmd in [['xclip', '-selection', 'clipboard', '-o'],
                    ['xsel', '--clipboard', '--output']]:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    return result.stdout
            except FileNotFoundError:
                continue
            except:
                pass
        return None

    @staticmethod
    def get_window() -> str:
        if SYSTEM == "Windows":
            try:
                import ctypes
                hwnd = ctypes.windll.user32.GetForegroundWindow()
                length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
                if length:
                    buf = ctypes.create_unicode_buffer(length + 1)
                    ctypes.windll.user32.GetWindowTextW(hwnd, buf, length + 1)
                    return buf.value
            except:
                pass
        elif SYSTEM == "Linux":
            try:
                result = subprocess.run(
                    ['xdotool', 'getactivewindow', 'getwindowname'],
                    capture_output=True, text=True, timeout=2
                )
                if result.returncode == 0:
                    return result.stdout.strip()
            except:
                pass
        elif SYSTEM == "Darwin":
            try:
                result = subprocess.run(
                    ['osascript', '-e',
                     'tell application "System Events" to get name of first application process whose frontmost is true'],
                    capture_output=True, text=True, timeout=2
                )
                if result.returncode == 0:
                    return result.stdout.strip()
            except:
                pass
        return "Unknown"


class PatternManager:
    def __init__(self):
        self.patterns: Dict[str, SecurityPattern] = {}
        self._load_from_file()

    def _load_from_file(self):
        if not HOOKS_FILE.exists():
            print(f"[WARN] {HOOKS_FILE} not found")
            return
        try:
            with open(HOOKS_FILE, 'r', encoding='utf-8') as f:
                for row in csv.DictReader(f):
                    name = row.get('name', '').strip()
                    pattern = row.get('pattern', '').strip()
                    if not name or not pattern:
                        continue
                    key = name.upper().replace(' ', '_').replace('-', '_')
                    threat_str = row.get('threat_level', 'HIGH').strip().upper()
                    try:
                        threat_level = ThreatLevel[threat_str]
                    except KeyError:
                        threat_level = ThreatLevel.HIGH
                    enabled = row.get('enabled', 'true').strip().lower() in ('true', '1', 'yes')
                    description = row.get('description', name).strip()
                    self.patterns[key] = SecurityPattern(
                        name=name, pattern=pattern, threat_level=threat_level,
                        description=description, enabled=enabled, is_builtin=True
                    )
            print(f"[OK] Loaded {len(self.patterns)} patterns from {HOOKS_FILE}")
        except Exception as e:
            print(f"[ERROR] Failed to load patterns: {e}")

    def save_to_file(self):
        try:
            with open(HOOKS_FILE, 'w', newline='', encoding='utf-8') as f:
                w = csv.DictWriter(f, fieldnames=['name', 'pattern', 'threat_level', 'description', 'enabled'])
                w.writeheader()
                for p in self.patterns.values():
                    w.writerow({
                        'name': p.name, 'pattern': p.pattern,
                        'threat_level': p.threat_level.name,
                        'description': p.description,
                        'enabled': 'true' if p.enabled else 'false'
                    })
            return True
        except Exception as e:
            print(f"[ERROR] {e}")
            return False

    def add_pattern(self, name, pattern, level, desc):
        key = name.upper().replace(' ', '_').replace('-', '_')
        self.patterns[key] = SecurityPattern(
            name=name, pattern=pattern, threat_level=level,
            description=desc, enabled=True, is_builtin=False
        )
        return self.save_to_file()

    def set_enabled(self, key, enabled):
        if key in self.patterns:
            self.patterns[key].enabled = enabled

    def get_enabled(self):
        return [p for p in self.patterns.values() if p.enabled]

    def reload(self):
        self.patterns.clear()
        self._load_from_file()


class NativeHook:
    """Cross-platform native hook loader"""

    def __init__(self, callback: Callable):
        self.callback = callback
        self.dll = None
        self.running = False
        self._thread = None
        self._ready = threading.Event()

        # Windows-specific
        self.hwnd = None
        self._wndproc = None

    def _load_dll(self) -> bool:
        if not DLL_PATH.exists():
            print(f"[ERROR] Native hook not found: {DLL_PATH}")
            return False

        try:
            if SYSTEM == "Windows":
                self.dll = ctypes.CDLL(str(DLL_PATH))
                self._setup_windows_signatures()
            else:
                self.dll = ctypes.CDLL(str(DLL_PATH))
                self._setup_unix_signatures()
            print("[OK] Native hook loaded")
            return True
        except Exception as e:
            print(f"[HOOK ERROR] {e}")
            return False

    def _setup_windows_signatures(self):
        from ctypes import wintypes
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

    def _setup_unix_signatures(self):
        # Unix uses char* instead of wchar_t*
        CALLBACK_TYPE = ctypes.CFUNCTYPE(None, ctypes.c_char_p)
        self.dll.InitHook.argtypes = [CALLBACK_TYPE]
        self.dll.InitHook.restype = ctypes.c_int
        self.dll.CleanupHook.argtypes = []
        self.dll.CleanupHook.restype = None
        self.dll.SetActive.argtypes = [ctypes.c_int]
        self.dll.SetActive.restype = None
        self.dll.IsActive.argtypes = []
        self.dll.IsActive.restype = ctypes.c_int
        self.dll.AddPattern.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
        self.dll.AddPattern.restype = ctypes.c_int
        self.dll.ClearPatterns.argtypes = []
        self.dll.ClearPatterns.restype = None
        self.dll.GetPatternCount.argtypes = []
        self.dll.GetPatternCount.restype = ctypes.c_int
        self.dll.ForceCheck.argtypes = []
        self.dll.ForceCheck.restype = ctypes.c_int

        # Store callback reference to prevent GC
        self._native_callback = CALLBACK_TYPE(self._unix_callback)

    def _unix_callback(self, threats_ptr):
        """Called from C on Linux/Mac"""
        try:
            threats = threats_ptr.decode('utf-8') if threats_ptr else "Unknown"
            self.callback("THREAT", threats)
        except Exception as e:
            print(f"[CALLBACK ERROR] {e}")

    def load_patterns(self, patterns: List[SecurityPattern]) -> int:
        if not self.dll:
            return 0
        self.dll.ClearPatterns()
        for p in patterns:
            if SYSTEM == "Windows":
                self.dll.AddPattern(p.name, p.pattern, p.enabled)
            else:
                self.dll.AddPattern(
                    p.name.encode('utf-8'),
                    p.pattern.encode('utf-8'),
                    1 if p.enabled else 0
                )
        count = self.dll.GetPatternCount()
        print(f"[OK] Loaded {count} patterns")
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
            self._run_windows()
        else:
            self._run_unix()

    def _run_windows(self):
        from ctypes import wintypes

        WM_USER = 0x0400
        WM_THREAT = WM_USER + 100

        if ctypes.sizeof(ctypes.c_void_p) == 8:
            LRESULT = ctypes.c_int64
            WPARAM = ctypes.c_uint64
            LPARAM = ctypes.c_int64
        else:
            LRESULT = ctypes.c_long
            WPARAM = ctypes.c_uint
            LPARAM = ctypes.c_long

        WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, WPARAM, LPARAM)

        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, WPARAM, LPARAM]
        user32.DefWindowProcW.restype = LRESULT

        class WNDCLASSEXW(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.UINT), ("style", wintypes.UINT),
                ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int), ("hInstance", wintypes.HINSTANCE),
                ("hIcon", wintypes.HICON), ("hCursor", wintypes.HANDLE),
                ("hbrBackground", wintypes.HBRUSH), ("lpszMenuName", wintypes.LPCWSTR),
                ("lpszClassName", wintypes.LPCWSTR), ("hIconSm", wintypes.HICON),
            ]

        hInst = kernel32.GetModuleHandleW(None)
        cn = f"StopSentinel{int(time.time() * 1000)}"

        def proc(hwnd, msg, wp, lp):
            if msg == WM_THREAT:
                try:
                    if wp:
                        s = ctypes.wstring_at(wp)
                        self.callback("THREAT", s)
                        try:
                            ctypes.windll.msvcrt.free(wp)
                        except:
                            pass
                except:
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
        self.hwnd = user32.CreateWindowExW(0, cn, "StopSentinel", 0, 0, 0, 0, 0, None, None, hInst, None)

        if not self.hwnd:
            print("[ERROR] Window creation failed")
            self._ready.set()
            return

        if not self.dll.InitHook(self.hwnd, WM_THREAT):
            print("[ERROR] InitHook failed")
            self._ready.set()
            return

        print("[OK] Windows hook started")
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
        if not self.dll.InitHook(self._native_callback):
            print("[ERROR] InitHook failed")
            self._ready.set()
            return

        print(f"[OK] {'macOS' if SYSTEM == 'Darwin' else 'Linux'} hook started")
        self._ready.set()

        # Keep thread alive
        while self.running:
            time.sleep(0.1)

        if self.dll:
            self.dll.CleanupHook()

    def set_active(self, active: bool):
        if self.dll:
            self.dll.SetActive(1 if active else 0)

    def force_check(self) -> bool:
        if self.dll:
            return bool(self.dll.ForceCheck())
        return False

    def stop(self):
        self.running = False
        if self.dll:
            self.dll.SetActive(0)
        if SYSTEM == "Windows" and self.hwnd:
            ctypes.windll.user32.PostMessageW(self.hwnd, 0x0012, 0, 0)


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("S.T.O.P Sentinel - DLP Agent v3.2")
        self.root.geometry("1200x700")
        self.root.minsize(1000, 600)
        self.root.configure(bg="#f8fafc")

        self.patterns = PatternManager()
        self.audit = AuditLogger()
        self.hook = NativeHook(self._on_event)

        self.active = False
        self.stats = {"blocked": 0, "start": None}
        self.tray_icon = None
        self.hidden = False

        self._setup_styles()
        self._build_menu()
        self._build_ui()

        self.hook.start()
        time.sleep(0.3)
        self.hook.load_patterns(self.patterns.get_enabled())

        self._start_timers()
        self.root.protocol("WM_DELETE_WINDOW", self._minimize_to_tray)
        self._create_tray_icon()

        # Set icon
        try:
            icon_path = APP_DIR / "icon.ico"
            if icon_path.exists() and SYSTEM == "Windows":
                self.root.iconbitmap(str(icon_path))
            else:
                icon_png = APP_DIR / "icon.png"
                if icon_png.exists():
                    img = tk.PhotoImage(file=str(icon_png))
                    self.root.iconphoto(True, img)
        except:
            pass

    def _create_tray_icon(self):
        try:
            import pystray
            from PIL import Image, ImageDraw

            img = Image.new('RGB', (64, 64), '#0f172a')
            dc = ImageDraw.Draw(img)
            dc.rectangle((8, 8, 56, 56), fill='#38bdf8')
            dc.text((20, 20), "S", fill='#0f172a')

            menu = pystray.Menu(
                pystray.MenuItem("Show Window", self._show_from_tray, default=True),
                pystray.MenuItem("Enable Protection", self._tray_toggle, checked=lambda item: self.active),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Exit", self._quit_app)
            )
            self.tray_icon = pystray.Icon("stop_sentinel", img, "STOP Sentinel", menu)
        except ImportError:
            print("[WARN] pystray not installed, tray icon disabled")

    def _minimize_to_tray(self):
        self.root.withdraw()
        self.hidden = True
        if self.tray_icon and not self.tray_icon.visible:
            threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def _show_from_tray(self, icon=None, item=None):
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        self.hidden = False

    def _tray_toggle(self, icon, item):
        self.root.after(0, self._toggle)

    def _quit_app(self, icon=None, item=None):
        if self.tray_icon:
            self.tray_icon.stop()
        self.hook.stop()
        self.audit.log(AuditEvent(
            timestamp=datetime.datetime.now().isoformat(),
            event_type="SYSTEM", source_app="STOP Sentinel",
            threat="N/A", level="INFO", action="CLOSED"
        ))
        self.root.quit()
        self.root.destroy()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Treeview", font=("Consolas", 9), rowheight=26)
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))

    def _build_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Logs", command=self._export)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._quit_app)

        policy_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Policy", menu=policy_menu)
        policy_menu.add_command(label="Configure Patterns", command=self._config)
        policy_menu.add_command(label="Add Pattern", command=self._add_pattern)
        policy_menu.add_separator()
        policy_menu.add_command(label="Reload from File", command=self._reload)
        policy_menu.add_command(label="Test Clipboard", command=self._test_clip)

    def _build_ui(self):
        sidebar = tk.Frame(self.root, bg="#0f172a", width=270)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        banner = tk.Frame(sidebar, bg="#1e293b")
        banner.pack(fill="x", padx=15, pady=(20, 10))

        banner_text = (
            "╔══════════════════════╗\n"
            "║   S.T.O.P SENTINEL   ║\n"
            "║   Sensitive Token    ║\n"
            "║   Obfuscation &      ║\n"
            "║   Protection         ║\n"
            "╚══════════════════════╝"
        )
        tk.Label(banner, text=banner_text, fg="#38bdf8", bg="#1e293b",
                 font=("Consolas", 10), justify="left").pack()

        platform_text = f"Clipboard DLP Agent ({SYSTEM})"
        tk.Label(sidebar, text=platform_text, fg="#94a3b8", bg="#0f172a",
                 font=("Segoe UI", 9)).pack(pady=(5, 15))

        self.btn_toggle = tk.Button(
            sidebar, text="▶  ENABLE PROTECTION", command=self._toggle,
            bg="#10b981", fg="white", font=("Segoe UI", 11, "bold"),
            relief="flat", padx=20, pady=12, cursor="hand2",
            activebackground="#059669", activeforeground="white"
        )
        self.btn_toggle.pack(pady=(5, 15), padx=20, fill="x")

        buttons = [
            ("⚙️  Configure", self._config, "#3b82f6"),
            ("➕  Add Pattern", self._add_pattern, "#8b5cf6"),
            ("🔄  Reload File", self._reload, "#06b6d4"),
            ("🧪  Test Clipboard", self._test_clip, "#f59e0b"),
            ("📊  Export Logs", self._export, "#6366f1"),
        ]
        for text, cmd, color in buttons:
            tk.Button(sidebar, text=text, command=cmd, bg=color, fg="white",
                      font=("Segoe UI", 10), relief="flat", pady=8, cursor="hand2",
                      activebackground=color, activeforeground="white"
                      ).pack(pady=3, padx=20, fill="x")

        tk.Frame(sidebar, bg="#1e293b", height=2).pack(fill="x", pady=20, padx=20)

        stats_frame = tk.Frame(sidebar, bg="#0f172a")
        stats_frame.pack(padx=20, fill="x")

        tk.Label(stats_frame, text="STATISTICS", fg="#94a3b8", bg="#0f172a",
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 10))

        self.stat_blocked = self._stat_row(stats_frame, "Threats Blocked", "0")
        self.stat_patterns = self._stat_row(stats_frame, "Active Patterns", str(len(self.patterns.get_enabled())))
        self.stat_uptime = self._stat_row(stats_frame, "Session Uptime", "00:00:00")

        tk.Label(sidebar, text=f"v3.2.0 ({SYSTEM})", fg="#475569", bg="#0f172a",
                 font=("Segoe UI", 8)).pack(side="bottom", pady=10)

        main = tk.Frame(self.root, bg="#f8fafc")
        main.pack(side="right", expand=True, fill="both")

        header = tk.Frame(main, bg="#ffffff", height=70)
        header.pack(fill="x", padx=20, pady=(20, 10))
        header.pack_propagate(False)

        self.lbl_status = tk.Label(header, text="●  PROTECTION DISABLED",
                                   fg="#ef4444", bg="#ffffff", font=("Segoe UI", 14, "bold"))
        self.lbl_status.pack(side="left", padx=20, pady=20)

        self.lbl_hook = tk.Label(header, text="Hook: Initializing...",
                                 fg="#64748b", bg="#ffffff", font=("Segoe UI", 10))
        self.lbl_hook.pack(side="right", padx=20)

        log_frame = tk.LabelFrame(main, text="  EVENT LOG  ", bg="#ffffff", fg="#1e293b",
                                  font=("Segoe UI", 11, "bold"), relief="groove")
        log_frame.pack(expand=True, fill="both", padx=20, pady=10)

        scrollbar = ttk.Scrollbar(log_frame, orient="vertical")
        scrollbar.pack(side="right", fill="y")

        columns = ("time", "event", "source", "threat", "level", "action")
        self.tree = ttk.Treeview(log_frame, columns=columns, show="headings",
                                 yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.tree.yview)

        widths = {"time": 80, "event": 100, "source": 180, "threat": 280, "level": 80, "action": 100}
        for col, w in widths.items():
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=w, anchor="w" if col in ("source", "threat") else "center")

        self.tree.pack(expand=True, fill="both", padx=5, pady=5)

        self.tree.tag_configure("CRITICAL", background="#fee2e2")
        self.tree.tag_configure("HIGH", background="#fed7aa")
        self.tree.tag_configure("MEDIUM", background="#fef3c7")
        self.tree.tag_configure("LOW", background="#dbeafe")
        self.tree.tag_configure("INFO", background="#f3f4f6")

        status_bar = tk.Frame(main, bg="#1e293b", height=28)
        status_bar.pack(fill="x", side="bottom")
        status_bar.pack_propagate(False)

        self.lbl_info = tk.Label(status_bar, text="Ready - Click 'ENABLE PROTECTION' to start",
                                 fg="#94a3b8", bg="#1e293b", font=("Segoe UI", 9))
        self.lbl_info.pack(side="left", padx=15, pady=5)

    def _stat_row(self, parent, label, value):
        frame = tk.Frame(parent, bg="#0f172a")
        frame.pack(fill="x", pady=3)
        tk.Label(frame, text=label, fg="#64748b", bg="#0f172a",
                 font=("Segoe UI", 9)).pack(side="left")
        val = tk.Label(frame, text=value, fg="#e2e8f0", bg="#0f172a",
                       font=("Segoe UI", 10, "bold"))
        val.pack(side="right")
        return val

    def _start_timers(self):
        self._update_uptime()
        self._update_hook_status()

    def _update_uptime(self):
        if self.active and self.stats["start"]:
            d = datetime.datetime.now() - self.stats["start"]
            h, r = divmod(int(d.total_seconds()), 3600)
            m, s = divmod(r, 60)
            self.stat_uptime.config(text=f"{h:02d}:{m:02d}:{s:02d}")
        self.root.after(1000, self._update_uptime)

    def _update_hook_status(self):
        if self.hook.dll:
            count = self.hook.dll.GetPatternCount()
            self.lbl_hook.config(text=f"Hook: Active ({count} patterns)", fg="#10b981")
        else:
            self.lbl_hook.config(text="Hook: Not loaded", fg="#ef4444")
        self.root.after(2000, self._update_hook_status)

    def _on_event(self, event_type, data):
        self.root.after(0, lambda: self._handle_event(event_type, data))

    def _handle_event(self, event_type, data):
        if event_type == "THREAT":
            self.stats["blocked"] += 1
            self.stat_blocked.config(text=str(self.stats["blocked"]))

            source = Clipboard.get_window()
            ts = datetime.datetime.now().strftime("%H:%M:%S")

            self.tree.insert("", 0, values=(ts, "BLOCKED", source[:30], data[:50], "CRITICAL", "REDACTED"),
                             tags=("CRITICAL",))

            self.audit.log(AuditEvent(
                timestamp=datetime.datetime.now().isoformat(),
                event_type="THREAT", source_app=source,
                threat=data, level="CRITICAL", action="BLOCKED"
            ))

            self._toast(data)
            self.lbl_info.config(text=f"BLOCKED: {data[:50]}")

    def _toast(self, message):
        toast = tk.Toplevel(self.root)
        toast.overrideredirect(True)
        toast.attributes("-topmost", True)
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        toast.geometry(f"400x70+{sw - 420}+{sh - 130}")
        toast.configure(bg="#dc2626")
        tk.Label(toast, text="🚨 SENSITIVE DATA BLOCKED", fg="white",
                 bg="#dc2626", font=("Segoe UI", 11, "bold")).pack(pady=(12, 4))
        tk.Label(toast, text=message[:45], fg="white", bg="#dc2626",
                 font=("Segoe UI", 9)).pack()
        self.root.after(3500, toast.destroy)

    def _toggle(self):
        self.active = not self.active
        self.hook.set_active(self.active)

        if self.active:
            self.btn_toggle.config(text="⏸  DISABLE PROTECTION", bg="#ef4444", activebackground="#dc2626")
            self.lbl_status.config(text="●  PROTECTION ACTIVE", fg="#10b981")
            self.stats["start"] = datetime.datetime.now()
            self.lbl_info.config(text="Monitoring clipboard for sensitive data...")
            self.audit.log(AuditEvent(
                timestamp=datetime.datetime.now().isoformat(),
                event_type="SYSTEM", source_app="STOP Sentinel",
                threat="N/A", level="INFO", action="ENABLED"
            ))
        else:
            self.btn_toggle.config(text="▶  ENABLE PROTECTION", bg="#10b981", activebackground="#059669")
            self.lbl_status.config(text="●  PROTECTION DISABLED", fg="#ef4444")
            self.lbl_info.config(text="Protection paused")
            self.audit.log(AuditEvent(
                timestamp=datetime.datetime.now().isoformat(),
                event_type="SYSTEM", source_app="STOP Sentinel",
                threat="N/A", level="INFO", action="DISABLED"
            ))

    def _reload(self):
        self.patterns.reload()
        count = self.hook.load_patterns(self.patterns.get_enabled())
        self.stat_patterns.config(text=str(count))
        messagebox.showinfo("Reload", f"Loaded {count} patterns from hooks.dlp")

    def _test_clip(self):
        clip = Clipboard.get_text()
        if not clip:
            messagebox.showinfo("Test", "Clipboard is empty")
            return
        if self.hook.dll:
            result = self.hook.force_check()
            if result:
                messagebox.showinfo("Test", "Threat found and redacted!")
            else:
                found = [p.name for p in self.patterns.get_enabled() if p.pattern.lower() in clip.lower()]
                if found:
                    messagebox.showwarning("Test", f"Pattern in clipboard: {', '.join(found)}")
                else:
                    messagebox.showinfo("Test", "No threats detected")
        else:
            messagebox.showerror("Test", "Native hook not loaded")

    def _config(self):
        win = tk.Toplevel(self.root)
        win.title("Pattern Configuration")
        win.geometry("700x500")
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
        canvas.create_window((0, 0), window=sf, anchor="nw", width=660)
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1 * (e.delta / 120)), "units"))

        pvars = {}
        for key in sorted(self.patterns.patterns.keys()):
            p = self.patterns.patterns[key]
            var = tk.BooleanVar(value=p.enabled)
            pvars[key] = var
            frame = tk.Frame(sf, bg="#ffffff", relief="solid", bd=1)
            frame.pack(fill="x", padx=5, pady=2)
            row = tk.Frame(frame, bg="#ffffff")
            row.pack(fill="x", padx=8, pady=6)
            tk.Checkbutton(row, text=p.name, variable=var, bg="#ffffff",
                           font=("Segoe UI", 10, "bold")).pack(side="left")
            tk.Label(row, text=p.threat_level.name, bg=p.threat_level.value, fg="white",
                     font=("Segoe UI", 7, "bold"), padx=6).pack(side="right")
            tk.Label(frame, text=f"Pattern: {p.pattern}", bg="#ffffff", fg="#64748b",
                     font=("Consolas", 8)).pack(anchor="w", padx=25, pady=(0, 6))

        bf = tk.Frame(win, bg="#f8fafc")
        bf.pack(fill="x", padx=10, pady=10)

        def save():
            for key, var in pvars.items():
                self.patterns.set_enabled(key, var.get())
            self.patterns.save_to_file()
            self.hook.load_patterns(self.patterns.get_enabled())
            self.stat_patterns.config(text=str(len(self.patterns.get_enabled())))
            canvas.unbind_all("<MouseWheel>")
            win.destroy()
            messagebox.showinfo("Saved", "Patterns saved to hooks.dlp")

        tk.Button(bf, text="Save", command=save, bg="#10b981", fg="white",
                  font=("Segoe UI", 10, "bold"), relief="flat", padx=20, pady=6).pack(side="right")
        tk.Button(bf, text="Cancel", command=lambda: (canvas.unbind_all("<MouseWheel>"), win.destroy()),
                  bg="#64748b", fg="white", font=("Segoe UI", 10), relief="flat", padx=20, pady=6
                  ).pack(side="right", padx=10)

    def _add_pattern(self):
        win = tk.Toplevel(self.root)
        win.title("Add Pattern")
        win.geometry("500x320")
        win.configure(bg="#f8fafc")
        win.transient(self.root)
        win.grab_set()

        tk.Label(win, text="Add New Pattern", bg="#1e293b", fg="white",
                 font=("Segoe UI", 12, "bold")).pack(fill="x", ipady=12)

        form = tk.Frame(win, bg="#ffffff")
        form.pack(expand=True, fill="both", padx=15, pady=15)

        tk.Label(form, text="Name:", bg="#ffffff", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(10, 3))
        en = tk.Entry(form, font=("Segoe UI", 10), width=45)
        en.pack(fill="x")

        tk.Label(form, text="Pattern (substring):", bg="#ffffff",
                 font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(15, 3))
        ep = tk.Entry(form, font=("Consolas", 10), width=45)
        ep.pack(fill="x")

        tk.Label(form, text="Description:", bg="#ffffff", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(15, 3))
        ed = tk.Entry(form, font=("Segoe UI", 10), width=45)
        ed.pack(fill="x")

        tk.Label(form, text="Threat Level:", bg="#ffffff", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(15, 3))
        lv = tk.StringVar(value="HIGH")
        lf = tk.Frame(form, bg="#ffffff")
        lf.pack(fill="x")
        for l in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            tk.Radiobutton(lf, text=l, variable=lv, value=l, bg="#ffffff").pack(side="left", padx=5)

        bf = tk.Frame(win, bg="#f8fafc")
        bf.pack(fill="x", padx=15, pady=15)

        def add():
            name, pattern, desc = en.get().strip(), ep.get().strip(), ed.get().strip()
            if not name or not pattern:
                messagebox.showerror("Error", "Name and pattern required", parent=win)
                return
            self.patterns.add_pattern(name, pattern, ThreatLevel[lv.get()], desc or name)
            self.hook.load_patterns(self.patterns.get_enabled())
            self.stat_patterns.config(text=str(len(self.patterns.get_enabled())))
            win.destroy()
            messagebox.showinfo("Added", f"'{name}' added to hooks.dlp")

        tk.Button(bf, text="Add", command=add, bg="#10b981", fg="white",
                  font=("Segoe UI", 10, "bold"), relief="flat", padx=20, pady=6).pack(side="right")
        tk.Button(bf, text="Cancel", command=win.destroy, bg="#64748b", fg="white",
                  font=("Segoe UI", 10), relief="flat", padx=20, pady=6).pack(side="right", padx=10)

    def _export(self):
        f = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if f:
            if self.audit.export(f):
                messagebox.showinfo("Export", f"Saved to {f}")
            else:
                messagebox.showwarning("Export", "No data or error")


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
            icon_path = APP_DIR / "icon.ico"
            if icon_path.exists():
                root.iconbitmap(str(icon_path))
        else:
            icon_path = APP_DIR / "icon.png"
            if icon_path.exists():
                img = tk.PhotoImage(file=str(icon_path))
                root.iconphoto(True, img)
    except:
        pass

    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
