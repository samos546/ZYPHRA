"""
Zyphra PC Check - FiveM PC check tool for server staff.

Read-only scanner. Runs locally, makes no network calls, modifies nothing.
Results are saved to a report the player chooses to share with staff.

Requirements (Windows 10/11, Python 3.10+):
    pip install customtkinter psutil

Build the EXE:
    pip install pyinstaller
    pyinstaller --noconsole --onefile --uac-admin --name Zyphra zyphra_pc_check.py

Optional: put a signatures.json next to the EXE to add your own keywords/hashes:
    {"high": ["mycheatname"], "medium": [], "low": [], "hashes": ["<sha256>"]}
"""

import ctypes
import datetime
import hashlib
import json
import os
import platform
import queue
import sys
import threading
import tkinter as tk
from dataclasses import asdict, dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk
import psutil

APP_NAME = "Zyphra PC Check"
VERSION = "1.0.0"

COLORS = {
    "bg": "#0b0d14",
    "panel": "#12151f",
    "card": "#181c2a",
    "accent": "#7c5cff",
    "accent_hover": "#6a4be8",
    "text": "#e6e8f0",
    "muted": "#7d8299",
    "high": "#ff4d6d",
    "medium": "#ffb020",
    "low": "#4da3ff",
    "info": "#7d8299",
}

DEFAULT_SIGNATURES = {
    "high": [
        "eulen", "redengine", "red engine", "susano", "hoax", "skript.gg",
        "skriptgg", "kiddion", "cheatengine", "cheat engine", "extreme injector",
        "xenos", "aimbot", "triggerbot", "wallhack", "lua executor", "luaexecutor",
        "tzx", "hydrogen menu", "hydrogenmenu",
    ],
    "medium": [
        "injector", "spoofer", "hwid", "executor", "modmenu", "mod menu",
        "trainer", "esp_", "noclip", "dll_inject", "manualmap", "manual map",
    ],
    "low": [
        "processhacker", "process hacker", "x64dbg", "ollydbg", "dnspy",
        "reclass", "hxd", "scylla",
    ],
}

SUSPECT_EXTENSIONS = {".exe", ".dll", ".sys", ".asi", ".lua", ".ini", ".cfg", ".bin"}
HASH_EXTENSIONS = {".exe", ".dll", ".sys", ".asi"}
MAX_FILES = 600_000
MAX_DEPTH = 7
MAX_HASH_SIZE = 80 * 1024 * 1024
SKIP_DIRS = {"$recycle.bin", "node_modules", ".git", "windows", "winsxs", "__pycache__"}


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    path: str = ""
    detail: str = ""


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent


def load_signatures() -> dict:
    sigs = {k: list(v) for k, v in DEFAULT_SIGNATURES.items()}
    sigs["hashes"] = []
    custom = app_dir() / "signatures.json"
    if custom.exists():
        try:
            data = json.loads(custom.read_text(encoding="utf-8"))
            for level in ("high", "medium", "low"):
                sigs[level] += [s.lower() for s in data.get(level, [])]
            sigs["hashes"] = [h.lower() for h in data.get("hashes", [])]
        except (OSError, json.JSONDecodeError):
            pass
    return sigs


def sha256_of(path: str) -> str | None:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


class Scanner:
    def __init__(self, sigs, options, out_queue, stop_event):
        self.sigs = sigs
        self.options = options
        self.q = out_queue
        self.stop = stop_event
        self.files_scanned = 0
        self.local = Path(os.environ.get("LOCALAPPDATA", ""))
        self.roaming = Path(os.environ.get("APPDATA", ""))
        self.home = Path.home()

    def emit(self, finding: Finding):
        self.q.put(("finding", finding))

    def progress(self, frac: float, text: str):
        self.q.put(("progress", frac, text))

    def match(self, text: str):
        text = text.lower()
        for level in ("high", "medium", "low"):
            for kw in self.sigs[level]:
                if kw in text:
                    return level, kw
        return None

    def run(self):
        steps = [
            ("processes", "Running processes", self.scan_processes),
            ("fivem", "FiveM folders and loaded modules", self.scan_fivem),
            ("prefetch", "Prefetch execution history", self.scan_prefetch),
            ("recent", "Recent files", self.scan_recent),
            ("files", "File system", self.scan_files),
        ]
        enabled = [s for s in steps if self.options.get(s[0])]
        for i, (_, label, fn) in enumerate(enabled):
            if self.stop.is_set():
                break
            self.progress(i / max(len(enabled), 1), f"Scanning: {label}")
            try:
                fn()
            except Exception as exc:  # one broken step must not kill the scan
                self.emit(Finding("info", "Error", f"{label} failed", detail=str(exc)))
        self.progress(1.0, "Scan stopped" if self.stop.is_set() else "Scan complete")
        self.q.put(("done", self.files_scanned))

    def scan_processes(self):
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            if self.stop.is_set():
                return
            info = proc.info
            name = info.get("name") or ""
            exe = info.get("exe") or ""
            hit = self.match(f"{name} {exe}")
            if hit:
                level, kw = hit
                self.emit(Finding(level, "Process", f"{name} (PID {info['pid']})", exe,
                                  f"Matched keyword '{kw}'"))

    def scan_fivem(self):
        app = self.local / "FiveM" / "FiveM.app"
        if not app.exists():
            self.emit(Finding("info", "FiveM", "FiveM.app folder not found", str(app)))
        else:
            for sub in ("plugins", "mods"):
                folder = app / sub
                if folder.exists():
                    for f in folder.rglob("*"):
                        if f.is_file():
                            sev = "medium" if f.suffix.lower() in {".dll", ".asi"} else "low"
                            self.emit(Finding(sev, "FiveM", f"File in FiveM {sub} folder",
                                              str(f), "Review: not normally present"))
            for f in app.glob("*"):
                if f.suffix.lower() == ".asi" or f.name.lower() == "dinput8.dll":
                    self.emit(Finding("medium", "FiveM", "ASI loader in FiveM root",
                                      str(f), "dinput8.dll / .asi files load third-party code"))
        trusted = tuple(p.lower() for p in (
            os.environ.get("WINDIR", r"C:\Windows"),
            os.environ.get("PROGRAMFILES", r"C:\Program Files"),
            os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
            str(app),
        ))
        for proc in psutil.process_iter(["pid", "name"]):
            if self.stop.is_set():
                return
            if not (proc.info.get("name") or "").lower().startswith("fivem"):
                continue
            try:
                maps = proc.memory_maps(grouped=True)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                self.emit(Finding("info", "FiveM", "Cannot read FiveM modules",
                                  detail="Run Zyphra as administrator"))
                continue
            for m in maps:
                path = m.path
                if not path.lower().endswith((".dll", ".asi")):
                    continue
                hit = self.match(path)
                if hit:
                    self.emit(Finding(hit[0], "Loaded DLL", Path(path).name, path,
                                      f"Matched keyword '{hit[1]}'"))
                elif not path.lower().startswith(trusted):
                    self.emit(Finding("low", "Loaded DLL", Path(path).name, path,
                                      "Loaded from a non-standard location"))

    def scan_prefetch(self):
        pf = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Prefetch"
        try:
            entries = list(pf.glob("*.pf"))
        except PermissionError:
            entries = []
        if not entries:
            self.emit(Finding("info", "Prefetch", "Prefetch not readable or empty",
                              str(pf), "Run as administrator"))
            return
        for f in entries:
            hit = self.match(f.name)
            if hit:
                ts = datetime.datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                self.emit(Finding(hit[0], "Prefetch", f.name, str(f),
                                  f"Executed on this PC, last seen {ts}. Keyword '{hit[1]}'"))

    def scan_recent(self):
        recent = self.roaming / "Microsoft" / "Windows" / "Recent"
        if not recent.exists():
            return
        for f in recent.glob("*.lnk"):
            hit = self.match(f.name)
            if hit:
                self.emit(Finding(hit[0], "Recent", f.name, str(f),
                                  f"Recently opened item. Keyword '{hit[1]}'"))

    def scan_files(self):
        roots = [
            self.home / "Downloads", self.home / "Desktop", self.home / "Documents",
            self.local / "Temp", self.local, self.roaming,
            Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")),
        ]
        seen_roots = set()
        hashes = set(self.sigs["hashes"])
        for root in roots:
            if self.stop.is_set() or not root.exists() or str(root) in seen_roots:
                continue
            seen_roots.add(str(root))
            base_depth = len(root.parts)
            for dirpath, dirnames, filenames in os.walk(root, topdown=True):
                if self.stop.is_set() or self.files_scanned >= MAX_FILES:
                    return
                dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS]
                if len(Path(dirpath).parts) - base_depth >= MAX_DEPTH:
                    dirnames[:] = []
                for fname in filenames:
                    self.files_scanned += 1
                    if self.files_scanned % 2000 == 0:
                        self.q.put(("count", self.files_scanned))
                    full = os.path.join(dirpath, fname)
                    ext = os.path.splitext(fname)[1].lower()
                    hit = self.match(fname)
                    if hit and (ext in SUSPECT_EXTENSIONS or hit[0] == "high"):
                        self.emit(Finding(hit[0], "File", fname, full,
                                          f"Filename matched '{hit[1]}'"))
                        continue
                    if hashes and ext in HASH_EXTENSIONS:
                        try:
                            if os.path.getsize(full) > MAX_HASH_SIZE:
                                continue
                        except OSError:
                            continue
                        digest = sha256_of(full)
                        if digest and digest in hashes:
                            self.emit(Finding("high", "Hash", fname, full,
                                              f"SHA-256 matches known cheat: {digest}"))


class GradientBar(tk.Canvas):
    """Animated horizontal gradient progress bar with a moving glow pulse."""

    def __init__(self, parent, width=760, height=10, **kwargs):
        super().__init__(parent, width=width, height=height, bg=COLORS["card"],
                         highlightthickness=0, **kwargs)
        self.w = width
        self.h = height
        self._frac = 0.0
        self._pulse_x = 0
        self._running = False
        self.bind("<Configure>", self._on_resize)
        self._draw()

    def _on_resize(self, event):
        self.w = event.width
        self._draw()

    def set(self, frac: float):
        self._frac = max(0.0, min(1.0, frac))
        self._draw()

    def start_pulse(self):
        if not self._running:
            self._running = True
            self._animate_pulse()

    def stop_pulse(self):
        self._running = False

    def _animate_pulse(self):
        if not self._running:
            return
        self._pulse_x = (self._pulse_x + 14) % (self.w + 120)
        self._draw()
        self.after(30, self._animate_pulse)

    def _draw(self):
        self.delete("all")
        self.create_rectangle(0, 0, self.w, self.h, fill=COLORS["card"], outline="")
        fill_w = int(self.w * self._frac)
        if fill_w > 1:
            steps = max(fill_w // 4, 1)
            c1, c2 = (124, 92, 255), (255, 77, 109)
            for i in range(steps):
                t = i / max(steps - 1, 1)
                r = int(c1[0] + (c2[0] - c1[0]) * t * 0.35)
                g = int(c1[1] + (c2[1] - c1[1]) * t * 0.35)
                b = int(c1[2] + (c2[2] - c1[2]) * t * 0.35)
                x0 = int(i * fill_w / steps)
                x1 = int((i + 1) * fill_w / steps)
                self.create_rectangle(x0, 0, x1, self.h, fill=f"#{r:02x}{g:02x}{b:02x}", outline="")
        if self._running:
            glow_x = self._pulse_x - 60
            self.create_oval(glow_x, -6, glow_x + 60, self.h + 6,
                             fill="", outline=COLORS["accent"], width=2)


class PulseDot(tk.Canvas):
    """Small breathing status dot."""

    def __init__(self, parent, color=COLORS["muted"], size=12):
        super().__init__(parent, width=size, height=size, bg=COLORS["panel"], highlightthickness=0)
        self.size = size
        self.color = color
        self._r = size // 3
        self._grow = True
        self._active = False
        self._draw()

    def set_color(self, color):
        self.color = color
        self._draw()

    def set_active(self, active: bool):
        self._active = active
        if active:
            self._animate()
        else:
            self._r = self.size // 3
            self._draw()

    def _animate(self):
        if not self._active:
            return
        step = 0.4
        max_r = self.size // 2 - 1
        min_r = self.size // 4
        if self._grow:
            self._r += step
            if self._r >= max_r:
                self._grow = False
        else:
            self._r -= step
            if self._r <= min_r:
                self._grow = True
        self._draw()
        self.after(40, self._animate)

    def _draw(self):
        self.delete("all")
        cx = cy = self.size / 2
        self.create_oval(cx - self._r, cy - self._r, cx + self._r, cy + self._r,
                         fill=self.color, outline="")


class ZyphraApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        self.title(f"{APP_NAME}  v{VERSION}")
        self.geometry("1180x740")
        self.minsize(1000, 640)
        self.configure(fg_color=COLORS["bg"])

        self.sigs = load_signatures()
        self.q = queue.Queue()
        self.stop_event = threading.Event()
        self.worker = None
        self.findings: list[Finding] = []
        self.started_at = None
        self.counts = {"high": 0, "medium": 0, "low": 0}
        self.options = {k: tk.BooleanVar(value=True) for k in
                        ("processes", "fivem", "prefetch", "recent", "files")}
        self._row_anim_queue = []
        self._logo_glow = 0
        self._logo_dir = 1

        self._build_header()
        self._build_sidebar()
        self._build_main()
        self._style_tree()
        self._animate_logo()
        self.after(150, self._consent)
        self.after(100, self._poll)
        self.after(40, self._process_row_animations)

    def _build_header(self):
        header = ctk.CTkFrame(self, height=64, corner_radius=0, fg_color=COLORS["panel"])
        header.pack(side="top", fill="x")
        header.pack_propagate(False)

        left = ctk.CTkFrame(header, fg_color="transparent")
        left.pack(side="left", padx=22, fill="y")
        self.logo_label = ctk.CTkLabel(left, text="◆", font=("Segoe UI", 22, "bold"),
                                       text_color=COLORS["accent"])
        self.logo_label.pack(side="left", pady=14)
        ctk.CTkLabel(left, text=" ZYPHRA", font=("Segoe UI", 18, "bold"),
                     text_color=COLORS["text"]).pack(side="left", pady=14)
        ctk.CTkLabel(left, text="  PC CHECK", font=("Segoe UI", 13),
                     text_color=COLORS["muted"]).pack(side="left", pady=16)

        right = ctk.CTkFrame(header, fg_color="transparent")
        right.pack(side="right", padx=22, fill="y")
        self.status_dot = PulseDot(right, color=COLORS["muted"])
        self.status_dot.pack(side="left", pady=24, padx=(0, 8))
        self.header_status = ctk.CTkLabel(right, text="Idle", font=("Segoe UI", 12, "bold"),
                                          text_color=COLORS["muted"])
        self.header_status.pack(side="left", pady=20)

    def _animate_logo(self):
        self._logo_glow += self._logo_dir * 6
        if self._logo_glow >= 255:
            self._logo_glow, self._logo_dir = 255, -1
        elif self._logo_glow <= 0:
            self._logo_glow, self._logo_dir = 0, 1
        base = (124, 92, 255)
        white_mix = self._logo_glow / 255
        r = int(base[0] + (255 - base[0]) * white_mix)
        g = int(base[1] + (255 - base[1]) * white_mix)
        b = int(base[2] + (255 - base[2]) * white_mix)
        self.logo_label.configure(text_color=f"#{r:02x}{g:02x}{b:02x}")
        self.after(60, self._animate_logo)

    def _consent(self):
        ok = messagebox.askokcancel(
            APP_NAME,
            "This tool scans this PC for cheat-related files, processes and traces.\n\n"
            "- It only READS data. Nothing is changed or deleted.\n"
            "- Nothing is sent over the internet.\n"
            "- The report is saved only where you choose.\n\n"
            "Continue?")
        if not ok:
            self.destroy()

    def _build_sidebar(self):
        side = ctk.CTkFrame(self, width=260, corner_radius=0, fg_color=COLORS["panel"])
        side.pack(side="left", fill="y")
        side.pack_propagate(False)

        ctk.CTkLabel(side, text="ZYPHRA", font=("Segoe UI", 30, "bold"),
                     text_color=COLORS["accent"]).pack(pady=(28, 0))
        ctk.CTkLabel(side, text="PC CHECK", font=("Segoe UI", 13, "bold"),
                     text_color=COLORS["muted"]).pack(pady=(0, 20))

        labels = {
            "processes": "Running processes",
            "fivem": "FiveM folders + DLLs",
            "prefetch": "Prefetch history",
            "recent": "Recent files",
            "files": "File system scan",
        }
        box = ctk.CTkFrame(side, fg_color=COLORS["card"], corner_radius=12)
        box.pack(fill="x", padx=18, pady=6)
        for key, text in labels.items():
            ctk.CTkCheckBox(box, text=text, variable=self.options[key],
                            fg_color=COLORS["accent"], hover_color=COLORS["accent_hover"],
                            text_color=COLORS["text"]).pack(anchor="w", padx=14, pady=8)

        self.start_btn = ctk.CTkButton(side, text="START SCAN", height=42, corner_radius=10,
                                       fg_color=COLORS["accent"], hover_color=COLORS["accent_hover"],
                                       font=("Segoe UI", 14, "bold"), command=self.start_scan)
        self.start_btn.pack(fill="x", padx=18, pady=(20, 6))
        self.stop_btn = ctk.CTkButton(side, text="STOP", height=36, corner_radius=10,
                                      fg_color=COLORS["card"], hover_color="#242a3f",
                                      state="disabled", command=self.stop_scan)
        self.stop_btn.pack(fill="x", padx=18, pady=4)
        self.export_btn = ctk.CTkButton(side, text="EXPORT REPORT", height=36, corner_radius=10,
                                        fg_color=COLORS["card"], hover_color="#242a3f",
                                        state="disabled", command=self.export_report)
        self.export_btn.pack(fill="x", padx=18, pady=4)

        admin = is_admin()
        ctk.CTkLabel(side, text="Administrator: " + ("YES" if admin else "NO (limited scan)"),
                     text_color=COLORS["low"] if admin else COLORS["medium"],
                     font=("Segoe UI", 12)).pack(side="bottom", pady=16)

    def _build_main(self):
        main = ctk.CTkFrame(self, fg_color=COLORS["bg"], corner_radius=0)
        main.pack(side="left", fill="both", expand=True, padx=20, pady=18)

        cards = ctk.CTkFrame(main, fg_color="transparent")
        cards.pack(fill="x")
        self.stat_labels = {}
        for key, title in (("high", "HIGH RISK"), ("medium", "REVIEW"), ("low", "LOW"),
                           ("files", "FILES SCANNED")):
            card = ctk.CTkFrame(cards, fg_color=COLORS["card"], corner_radius=14)
            card.pack(side="left", fill="x", expand=True, padx=(0, 10))
            color = COLORS.get(key, COLORS["text"])
            lbl = ctk.CTkLabel(card, text="0", font=("Segoe UI", 28, "bold"), text_color=color)
            lbl.pack(pady=(12, 0))
            ctk.CTkLabel(card, text=title, font=("Segoe UI", 11, "bold"),
                         text_color=COLORS["muted"]).pack(pady=(0, 12))
            self.stat_labels[key] = lbl

        self.status = ctk.CTkLabel(main, text="Ready.", anchor="w", text_color=COLORS["muted"])
        self.status.pack(fill="x", pady=(14, 4))
        self.bar = GradientBar(main, height=10)
        self.bar.pack(fill="x", pady=(0, 12))

        frame = ctk.CTkFrame(main, fg_color=COLORS["card"], corner_radius=14)
        frame.pack(fill="both", expand=True)
        cols = ("severity", "category", "title", "detail", "path")
        self.tree = ttk.Treeview(frame, columns=cols, show="headings", selectmode="browse")
        widths = {"severity": 80, "category": 100, "title": 220, "detail": 260, "path": 380}
        for c in cols:
            self.tree.heading(c, text=c.upper())
            self.tree.column(c, width=widths[c], anchor="w")
        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=8)
        scroll.pack(side="right", fill="y", pady=8, padx=(0, 4))
        self.tree.bind("<Double-1>", self._open_location)

    def _style_tree(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Treeview", background=COLORS["card"], fieldbackground=COLORS["card"],
                        foreground=COLORS["text"], rowheight=28, borderwidth=0,
                        font=("Segoe UI", 10))
        style.configure("Treeview.Heading", background=COLORS["panel"], foreground=COLORS["muted"],
                        font=("Segoe UI", 9, "bold"), borderwidth=0, relief="flat")
        style.map("Treeview", background=[("selected", "#2a2f47")])
        style.configure("Vertical.TScrollbar", background=COLORS["panel"],
                        troughcolor=COLORS["card"], bordercolor=COLORS["card"], arrowcolor=COLORS["muted"])
        for sev in ("high", "medium", "low", "info"):
            self.tree.tag_configure(sev, foreground=COLORS[sev])

    def start_scan(self):
        if self.worker and self.worker.is_alive():
            return
        if not any(v.get() for v in self.options.values()):
            messagebox.showwarning(APP_NAME, "Select at least one scan module.")
            return
        self.tree.delete(*self.tree.get_children())
        self.findings.clear()
        self.counts = {"high": 0, "medium": 0, "low": 0}
        for k in self.stat_labels:
            self.stat_labels[k].configure(text="0")
        self.stop_event.clear()
        self.started_at = datetime.datetime.now()
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.export_btn.configure(state="disabled")
        self.status_dot.set_color(COLORS["accent"])
        self.status_dot.set_active(True)
        self.header_status.configure(text="Scanning...", text_color=COLORS["accent"])
        self.bar.start_pulse()
        scanner = Scanner(self.sigs, {k: v.get() for k, v in self.options.items()},
                          self.q, self.stop_event)
        self.worker = threading.Thread(target=scanner.run, daemon=True)
        self.worker.start()

    def stop_scan(self):
        self.stop_event.set()
        self.status.configure(text="Stopping...")
        self.header_status.configure(text="Stopping...", text_color=COLORS["medium"])

    def _poll(self):
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "finding":
                    self._add_finding(msg[1])
                elif kind == "progress":
                    self.bar.set(msg[1])
                    self.status.configure(text=msg[2])
                elif kind == "count":
                    self.stat_labels["files"].configure(text=f"{msg[1]:,}")
                elif kind == "done":
                    self.stat_labels["files"].configure(text=f"{msg[1]:,}")
                    self.start_btn.configure(state="normal")
                    self.stop_btn.configure(state="disabled")
                    self.export_btn.configure(state="normal")
                    self.bar.stop_pulse()
                    self.status_dot.set_active(False)
                    if self.counts["high"] > 0:
                        self.status_dot.set_color(COLORS["high"])
                        self.header_status.configure(text=f"{self.counts['high']} high-risk finding(s)",
                                                     text_color=COLORS["high"])
                    elif self.counts["medium"] > 0:
                        self.status_dot.set_color(COLORS["medium"])
                        self.header_status.configure(text="Review recommended", text_color=COLORS["medium"])
                    else:
                        self.status_dot.set_color(COLORS["low"])
                        self.header_status.configure(text="Clean scan", text_color=COLORS["low"])
        except queue.Empty:
            pass
        self.after(100, self._poll)

    def _add_finding(self, f: Finding):
        self.findings.append(f)
        if f.severity in self.counts:
            self.counts[f.severity] += 1
            self.stat_labels[f.severity].configure(text=str(self.counts[f.severity]))
        item = self.tree.insert("", "end",
                                values=(f.severity.upper(), f.category, f.title, f.detail, f.path),
                                tags=(f.severity, "flash"))
        self._row_anim_queue.append((item, 0))

    def _process_row_animations(self):
        style = ttk.Style(self)
        still_going = []
        for item, step in self._row_anim_queue:
            if not self.tree.exists(item):
                continue
            if step < 4:
                tag = f"flash{step}"
                fade = ["#3a2f66", "#2d2750", "#221f3f", COLORS["card"]]
                style.configure(f"flash{step}.Treeview")
                self.tree.tag_configure(tag, background=fade[step])
                current_tags = list(self.tree.item(item, "tags"))
                current_tags = [t for t in current_tags if not t.startswith("flash")]
                current_tags.append(tag)
                self.tree.item(item, tags=tuple(current_tags))
                still_going.append((item, step + 1))
        self._row_anim_queue = still_going
        self.after(90, self._process_row_animations)

    def _open_location(self, _event):
        sel = self.tree.selection()
        if not sel:
            return
        path = self.tree.item(sel[0], "values")[4]
        target = Path(path)
        if target.exists() and hasattr(os, "startfile"):
            os.startfile(target if target.is_dir() else target.parent)

    def export_report(self):
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", initialfile=f"zyphra_report_{stamp}",
            filetypes=[("Text report", "*.txt"), ("JSON report", "*.json")])
        if not path:
            return
        meta = {
            "tool": f"{APP_NAME} v{VERSION}",
            "machine": platform.node(),
            "user": os.environ.get("USERNAME", ""),
            "os": platform.platform(),
            "admin": is_admin(),
            "scan_started": self.started_at.isoformat(timespec="seconds") if self.started_at else "",
            "scan_finished": datetime.datetime.now().isoformat(timespec="seconds"),
            "counts": self.counts,
        }
        if path.lower().endswith(".json"):
            payload = {"meta": meta, "findings": [asdict(f) for f in self.findings]}
            Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        else:
            lines = [f"{APP_NAME} report", "=" * 60]
            lines += [f"{k}: {v}" for k, v in meta.items()]
            lines += ["", "FINDINGS", "-" * 60]
            order = {"high": 0, "medium": 1, "low": 2, "info": 3}
            for f in sorted(self.findings, key=lambda x: order.get(x.severity, 9)):
                lines.append(f"[{f.severity.upper()}] {f.category} | {f.title}")
                if f.detail:
                    lines.append(f"    {f.detail}")
                if f.path:
                    lines.append(f"    {f.path}")
            lines += ["", "Note: matches are leads for staff review, not proof of cheating."]
            Path(path).write_text("\n".join(lines), encoding="utf-8")
        messagebox.showinfo(APP_NAME, f"Report saved:\n{path}")


if __name__ == "__main__":
    if platform.system() != "Windows":
        print("Zyphra PC Check is built for Windows.")
        sys.exit(1)
    ZyphraApp().mainloop()
