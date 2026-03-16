import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import ctypes
from ctypes import wintypes
import threading
import datetime
import json
import csv
import time
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import pystray
from PIL import Image, ImageDraw
import io


# ================================
# PATHS
# ================================
APP_DIR = Path(__file__).parent
HOOKS_FILE = APP_DIR / "hooks.dlp"
LOGS_DIR = APP_DIR / "promptsec_logs"
DLL_PATH = APP_DIR / "promptsec_hook.dll"

LOGS_DIR.mkdir(exist_ok=True)

# ================================
# WINDOWS CONSTANTS
# ================================
WM_USER = 0x0400
WM_THREAT_DETECTED = WM_USER + 100
CF_UNICODETEXT = 13

# ================================
# WINDOWS API
# ================================
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
        ("cbSize", wintypes.UINT),
        ("style", wintypes.UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HICON),
        ("hCursor", wintypes.HANDLE),
        ("hbrBackground", wintypes.HBRUSH),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
        ("hIconSm", wintypes.HICON),
    ]


user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, WPARAM, LPARAM]
user32.DefWindowProcW.restype = LRESULT


# ================================
# THREAT LEVEL
# ================================
class ThreatLevel(Enum):
    CRITICAL = "#dc2626"
    HIGH = "#ea580c"
    MEDIUM = "#f59e0b"
    LOW = "#3b82f6"
    INFO = "#6b7280"


# ================================
# PATTERN
# ================================
@dataclass
class SecurityPattern:
    name: str
    pattern: str
    threat_level: ThreatLevel
    description: str
    enabled: bool = True
    is_builtin: bool = True


# ================================
# AUDIT LOGGER
# ================================
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


# ================================
# CLIPBOARD
# ================================
class Clipboard:
    @staticmethod
    def get_text() -> Optional[str]:
        try:
            user32.OpenClipboard.argtypes = [wintypes.HWND]
            user32.OpenClipboard.restype = wintypes.BOOL
            user32.GetClipboardData.argtypes = [wintypes.UINT]
            user32.GetClipboardData.restype = wintypes.HANDLE
            kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
            kernel32.GlobalLock.restype = ctypes.c_void_p
            kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]

            if not user32.OpenClipboard(None):
                return None
            try:
                h = user32.GetClipboardData(CF_UNICODETEXT)
                if h:
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
    def get_window() -> str:
        try:
            hwnd = user32.GetForegroundWindow()
            length = user32.GetWindowTextLengthW(hwnd)
            if length:
                buf = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buf, length + 1)
                return buf.value
        except:
            pass
        return "Unknown"


# ================================
# PATTERN MANAGER - Loads from hooks.dlp
# ================================
class PatternManager:
    def __init__(self):
        self.patterns: Dict[str, SecurityPattern] = {}
        self._load_from_file()

    def _load_from_file(self):
        """Load all patterns from hooks.dlp file"""
        if not HOOKS_FILE.exists():
            print(f"[WARN] {HOOKS_FILE} not found. No patterns loaded.")
            return

        try:
            with open(HOOKS_FILE, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
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

                    enabled_str = row.get('enabled', 'true').strip().lower()
                    enabled = enabled_str in ('true', '1', 'yes')

                    description = row.get('description', name).strip()

                    self.patterns[key] = SecurityPattern(
                        name=name,
                        pattern=pattern,
                        threat_level=threat_level,
                        description=description,
                        enabled=enabled,
                        is_builtin=True
                    )

            print(f"[OK] Loaded {len(self.patterns)} patterns from {HOOKS_FILE}")

        except Exception as e:
            print(f"[ERROR] Failed to load patterns: {e}")

    def save_to_file(self):
        """Save all patterns back to hooks.dlp"""
        try:
            with open(HOOKS_FILE, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['name', 'pattern', 'threat_level', 'description', 'enabled'])
                writer.writeheader()

                for p in self.patterns.values():
                    writer.writerow({
                        'name': p.name,
                        'pattern': p.pattern,
                        'threat_level': p.threat_level.name,
                        'description': p.description,
                        'enabled': 'true' if p.enabled else 'false'
                    })

            print(f"[OK] Saved {len(self.patterns)} patterns to {HOOKS_FILE}")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to save patterns: {e}")
            return False

    def add_pattern(self, name: str, pattern: str, level: ThreatLevel, desc: str) -> bool:
        key = name.upper().replace(' ', '_').replace('-', '_')
        self.patterns[key] = SecurityPattern(
            name=name,
            pattern=pattern,
            threat_level=level,
            description=desc,
            enabled=True,
            is_builtin=False
        )
        return self.save_to_file()

    def remove_pattern(self, key: str) -> bool:
        if key in self.patterns:
            del self.patterns[key]
            return self.save_to_file()
        return False

    def set_enabled(self, key: str, enabled: bool):
        if key in self.patterns:
            self.patterns[key].enabled = enabled

    def get_enabled(self) -> List[SecurityPattern]:
        return [p for p in self.patterns.values() if p.enabled]

    def reload(self):
        self.patterns.clear()
        self._load_from_file()


# ================================
# C HOOK MANAGER
# ================================
class CHook:
    def __init__(self, callback):
        self.callback = callback
        self.dll = None
        self.hwnd = None
        self.running = False
        self._wndproc = None
        self._thread = None
        self._ready = threading.Event()

    def _load_dll(self) -> bool:
        if not DLL_PATH.exists():
            print(f"[ERROR] DLL not found: {DLL_PATH}")
            return False

        try:
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
            self.dll.TestPattern.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
            self.dll.TestPattern.restype = wintypes.BOOL

            print("[OK] DLL loaded")
            return True
        except Exception as e:
            print(f"[DLL ERROR] {e}")
            return False

    def load_patterns(self, patterns: List[SecurityPattern]) -> int:
        if not self.dll:
            return 0

        self.dll.ClearPatterns()

        for p in patterns:
            self.dll.AddPattern(p.name, p.pattern, p.enabled)

        count = self.dll.GetPatternCount()
        print(f"[OK] Loaded {count} patterns into DLL")
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
        hInst = kernel32.GetModuleHandleW(None)
        cn = f"PromptSec{int(time.time() * 1000)}"

        def proc(hwnd, msg, wp, lp):
            if msg == WM_THREAT_DETECTED:
                try:
                    if wp:
                        s = ctypes.wstring_at(wp)
                        self.callback("THREAT", s)
                        try:
                            ctypes.windll.msvcrt.free(wp)
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

        self.hwnd = user32.CreateWindowExW(0, cn, "PromptSec", 0, 0, 0, 0, 0, None, None, hInst, None)

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

    def set_active(self, active: bool):
        if self.dll:
            self.dll.SetActive(active)

    def force_check(self) -> bool:
        if self.dll:
            return self.dll.ForceCheck()
        return False

    def stop(self):
        self.running = False
        if self.dll:
            self.dll.SetActive(False)
        if self.hwnd:
            user32.PostMessageW(self.hwnd, 0x0012, 0, 0)


# ================================
# MAIN APPLICATION
# ================================
class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("S.T.O.P Sentinel - DLP Agent v3.2")
        self.root.geometry("1200x700")
        self.root.minsize(1000, 600)
        self.root.configure(bg="#f8fafc")

        self.patterns = PatternManager()
        self.audit = AuditLogger()
        self.hook = CHook(self._on_event)

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
        # self.root.protocol("WM_DELETE_WINDOW", self._close)
        self.root.protocol("WM_DELETE_WINDOW", self._minimize_to_tray)
        # Create system tray icon
        self._create_tray_icon()
        try:
            self.root.iconbitmap('icon.ico')
        except:
            pass  # Ignore if icon not found

        try:
            import ctypes
            myappid = 'com.stopsentinel.dlp.agent.3.2'
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
            print("In App Init")

            # Try to load icon file if exists
            icon_path = Path(__file__).parent / "icon.ico"
            if icon_path.exists():
                self.root.iconbitmap(str(icon_path))
            else:
                # Create icon programmatically
                self._create_window_icon()
        except Exception as e:
            print(f"[ICON] Could not set icon: {e}")

    def _create_tray_icon(self):
        """Create system tray icon"""

        # Create simple icon
        def create_icon():
            width = 64
            height = 64
            color1 = "#38bdf8"
            color2 = "#0f172a"

            image = Image.new('RGB', (width, height), color2)
            dc = ImageDraw.Draw(image)
            dc.rectangle((8, 8, 56, 56), fill=color1)
            dc.text((20, 20), "S", fill=color2)
            return image

        icon_image = create_icon()

        # Create menu
        menu = pystray.Menu(
            pystray.MenuItem("Show Window", self._show_from_tray, default=True),
            pystray.MenuItem("Enable Protection", self._tray_toggle, checked=lambda item: self.active),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Statistics", self._show_stats),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit", self._quit_app)
        )

        self.tray_icon = pystray.Icon("stop_sentinel", icon_image, "STOP Sentinel", menu)

    def _minimize_to_tray(self):
        """Minimize to system tray instead of closing"""
        self.root.withdraw()
        self.hidden = True

        # Start tray icon if not running
        if self.tray_icon and not self.tray_icon.visible:
            threading.Thread(target=self.tray_icon.run, daemon=True).start()

        self._show_balloon("STOP Sentinel", "Running in background. Right-click tray icon to restore.")

    def _show_from_tray(self, icon=None, item=None):
        """Restore window from tray"""
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        self.hidden = False

    def _tray_toggle(self, icon, item):
        """Toggle protection from tray menu"""
        self.root.after(0, self._toggle)

    def _show_stats(self, icon=None, item=None):
        """Show statistics balloon"""
        stats_text = f"Blocked: {self.stats['blocked']} | Patterns: {len(self.patterns.get_enabled())}"
        self._show_balloon("STOP Sentinel Statistics", stats_text)

    def _show_balloon(self, title, message):
        """Show system tray notification"""
        if self.tray_icon:
            self.tray_icon.notify(message, title)

    def _quit_app(self, icon=None, item=None):
        """Completely exit application"""
        if self.active:
            # Ask confirmation via messagebox
            self.root.after(0, self._confirm_exit)
        else:
            self._do_quit()

    def _confirm_exit(self):
        self._show_from_tray()
        if messagebox.askyesno("Confirm Exit", "Protection is active. Really exit?"):
            self._do_quit()

    def _do_quit(self):
        """Actually quit the application"""
        if self.tray_icon:
            self.tray_icon.stop()

        self.hook.stop()

        self.audit.log(AuditEvent(
            timestamp=datetime.datetime.now().isoformat(),
            event_type="SYSTEM", source_app="STOP Sentinel",
            threat="N/A", level="INFO", action="APPLICATION_CLOSED"
        ))

        self.root.quit()
        self.root.destroy()

        # Update existing _close method

    def _close(self):
        """Called when X button clicked - now minimizes to tray"""
        self._minimize_to_tray()


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
        file_menu.add_command(label="Exit", command=self._close)

        policy_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Policy", menu=policy_menu)
        policy_menu.add_command(label="Configure Patterns", command=self._config)
        policy_menu.add_command(label="Add Pattern", command=self._add_pattern)
        policy_menu.add_separator()
        policy_menu.add_command(label="Reload from File", command=self._reload)
        policy_menu.add_command(label="Test Clipboard", command=self._test_clip)

    def _build_ui(self):
        # Sidebar
        sidebar = tk.Frame(self.root, bg="#0f172a", width=270)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)


        banner = tk.Frame(sidebar, bg="#1e293b")
        banner.pack(fill="x", padx=15, pady=(20, 10))

        banner_text ="""
╔══════════════════════╗
║   S.T.O.P SENTINEL   ║
║   Sensitive Token    ║
║   Obfuscation &      ║
║   Protection         ║
╚══════════════════════╝"""

        tk.Label(banner, text=banner_text, fg="#38bdf8", bg="#1e293b",
                 font=("Consolas", 10), justify="left").pack()

        tk.Label(sidebar, text="Clipboard DLP Agent", fg="#94a3b8", bg="#0f172a",
                 font=("Segoe UI", 9)).pack(pady=(5, 15))

        # START/STOP Toggle Button
        self.btn_toggle = tk.Button(
            sidebar, text="▶  ENABLE PROTECTION", command=self._toggle,
            bg="#10b981", fg="white", font=("Segoe UI", 11, "bold"),
            relief="flat", padx=20, pady=12, cursor="hand2",
            activebackground="#059669", activeforeground="white"
        )
        self.btn_toggle.pack(pady=(5, 15), padx=20, fill="x")

        # Other buttons
        buttons = [
            ("⚙️  Configure", self._config, "#3b82f6"),
            ("➕  Add Pattern", self._add_pattern, "#8b5cf6"),
            ("🔄  Reload File", self._reload, "#06b6d4"),
            ("🧪  Test Clipboard", self._test_clip, "#f59e0b"),
            ("📊  Export Logs", self._export, "#6366f1"),
        ]
        for text, cmd, color in buttons:
            tk.Button(
                sidebar, text=text, command=cmd, bg=color, fg="white",
                font=("Segoe UI", 10), relief="flat", pady=8, cursor="hand2",
                activebackground=color, activeforeground="white"
            ).pack(pady=3, padx=20, fill="x")

        # Separator
        tk.Frame(sidebar, bg="#1e293b", height=2).pack(fill="x", pady=20, padx=20)

        # Statistics
        stats_frame = tk.Frame(sidebar, bg="#0f172a")
        stats_frame.pack(padx=20, fill="x")

        tk.Label(stats_frame, text="STATISTICS", fg="#94a3b8", bg="#0f172a",
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 10))

        self.stat_blocked = self._stat_row(stats_frame, "Threats Blocked", "0")
        self.stat_patterns = self._stat_row(stats_frame, "Active Patterns", str(len(self.patterns.get_enabled())))
        self.stat_uptime = self._stat_row(stats_frame, "Session Uptime", "00:00:00")

        # Version
        tk.Label(sidebar, text="v3.2.0", fg="#475569", bg="#0f172a",
                 font=("Segoe UI", 8)).pack(side="bottom", pady=10)

        # ===== MAIN CONTENT =====
        main = tk.Frame(self.root, bg="#f8fafc")
        main.pack(side="right", expand=True, fill="both")

        # Header
        header = tk.Frame(main, bg="#ffffff", height=70)
        header.pack(fill="x", padx=20, pady=(20, 10))
        header.pack_propagate(False)

        self.lbl_status = tk.Label(
            header, text="●  PROTECTION DISABLED",
            fg="#ef4444", bg="#ffffff", font=("Segoe UI", 14, "bold")
        )
        self.lbl_status.pack(side="left", padx=20, pady=20)

        self.lbl_hook = tk.Label(
            header, text="Hook: Initializing...",
            fg="#64748b", bg="#ffffff", font=("Segoe UI", 10)
        )
        self.lbl_hook.pack(side="right", padx=20)

        # Event Log
        log_frame = tk.LabelFrame(
            main, text="  EVENT LOG  ", bg="#ffffff", fg="#1e293b",
            font=("Segoe UI", 11, "bold"), relief="groove"
        )
        log_frame.pack(expand=True, fill="both", padx=20, pady=10)

        scrollbar = ttk.Scrollbar(log_frame, orient="vertical")
        scrollbar.pack(side="right", fill="y")

        columns = ("time", "event", "source", "threat", "level", "action")
        self.tree = ttk.Treeview(
            log_frame, columns=columns, show="headings",
            yscrollcommand=scrollbar.set
        )
        scrollbar.config(command=self.tree.yview)

        widths = {"time": 80, "event": 100, "source": 180, "threat": 280, "level": 80, "action": 100}
        for col, w in widths.items():
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=w, anchor="w" if col in ("source", "threat") else "center")

        self.tree.pack(expand=True, fill="both", padx=5, pady=5)

        # Row colors
        self.tree.tag_configure("CRITICAL", background="#fee2e2")
        self.tree.tag_configure("HIGH", background="#fed7aa")
        self.tree.tag_configure("MEDIUM", background="#fef3c7")
        self.tree.tag_configure("LOW", background="#dbeafe")
        self.tree.tag_configure("INFO", background="#f3f4f6")

        # Status Bar
        status_bar = tk.Frame(main, bg="#1e293b", height=28)
        status_bar.pack(fill="x", side="bottom")
        status_bar.pack_propagate(False)

        self.lbl_info = tk.Label(
            status_bar, text="Ready - Click 'ENABLE PROTECTION' to start",
            fg="#94a3b8", bg="#1e293b", font=("Segoe UI", 9)
        )
        self.lbl_info.pack(side="left", padx=15, pady=5)


    def _stat_row(self, parent, label: str, value: str) -> tk.Label:
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

    def _on_event(self, event_type: str, data: str):
        self.root.after(0, lambda: self._handle_event(event_type, data))

    def _handle_event(self, event_type: str, data: str):
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


    def _toast(self, message: str):
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
                found = []
                for p in self.patterns.get_enabled():
                    if p.pattern.lower() in clip.lower():
                        found.append(p.name)

                if found:
                    messagebox.showwarning("Test", f"Pattern in clipboard: {', '.join(found)}\nCheck DLL.")
                else:
                    messagebox.showinfo("Test", "No threats detected")
        else:
            messagebox.showerror("Test", "DLL not loaded")

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
                  bg="#64748b", fg="white", font=("Segoe UI", 10), relief="flat", padx=20, pady=6).pack(side="right",
                                                                                                        padx=10)

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

        tk.Label(form, text="Pattern (substring to match):", bg="#ffffff",
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

    def _close(self):
        if self.active:
            if not messagebox.askyesno("Exit", "Protection active. Exit?"):
                return
        self.hook.stop()
        self.root.destroy()


# ================================
# MAIN
# ================================
def main():

    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID('stop.sentinel.dlp')

    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except:
        pass

    root = tk.Tk()
    root.iconbitmap('icon.ico')  # Must be .ico file in same folder

    App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
