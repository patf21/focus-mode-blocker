"""
Study Mode – Focus Blocker (Windows) [HOSTS-ONLY + crash failsafe, AV-friendly]

Key points:
- NO auto-UAC elevation (run UI as Admin when you want to start focus mode).
- HOSTS-only blocking; no Program Files writes; no browser policy writes.
- Exactly TWO processes during focus mode:
    1) UI process
    2) ONE combined Worker+Watcher process (does blocking + watches UI PID; cleans up if UI dies)
  -> "dont open a separate worker if theres a watcher" satisfied (watcher is inside worker).
- Crash failsafe:
    - Startup recovery: if last run didn't exit cleanly, auto-unblock.
    - Aggressive unblock: removes marked block section + any hosts entries for target domains.
    - Flush DNS cache on cleanup/recovery.
"""

import atexit
import ctypes
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox

import psutil
import winsound

def ding_start():
    # higher pitch, shorter
    try:
        winsound.Beep(880, 180)
        winsound.Beep(880, 180)
    except Exception:
        pass

def ding_stop():
    # lower pitch, longer
    try:
        winsound.Beep(440, 220)
        winsound.Beep(330, 220)
    except Exception:
        pass


# ============================================================
# CONFIG
# ============================================================

APP_NAME = "StudyModeFocusBlocker"

STOP_PHRASE = "The quick brown fox jumps over the lazy dog"
REQUIRE_STOP_PHRASE = True

HOSTS_BLOCK_ENTRIES = [
    # YouTube
    "youtube.com",
    "www.youtube.com",
    "m.youtube.com",
    "youtu.be",
    "googlevideo.com",
    "ytimg.com",
    "i.ytimg.com",

    # Discord (network block; no kill loop)
    "discord.com",
    "www.discord.com",
    "discord.gg",
    "cdn.discordapp.com",
    "media.discordapp.net",

    # Instagram
    "instagram.com",
    "www.instagram.com",
    "graph.instagram.com",
    "cdninstagram.com",

    # Reddit
    "reddit.com",
    "www.reddit.com",
    "old.reddit.com",
    "new.reddit.com",
    "redd.it",

    # LinkedIn
    "linkedin.com",
    "www.linkedin.com",
    "lnkd.in",
]

CLOSE_DISCORD_ON_START = True
DISCORD_PROCESS_NAMES = {"Discord.exe", "Update.exe"}

HEARTBEAT_INTERVAL_SEC = 2.0

# Markers (support both correct + old typo)
HOSTS_MARK_START = "# --- STUDYMODE_FOCUS_BLOCKER_START ---"
HOSTS_MARK_START_OLD = "# --- STUDYDDYMODE_FOCUS_BLOCKER_START ---"  # old typo marker
HOSTS_MARK_END = "# --- STUDYMODE_FOCUS_BLOCKER_END ---"

# Session lock for crash recovery
SESSION_LOCK_FILENAME = "focusmode.session.json"


# ============================================================
# PATHS / LOGGING
# ============================================================

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def app_data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or str(Path.home())
    p = Path(base) / APP_NAME
    p.mkdir(parents=True, exist_ok=True)
    return p

def log_path() -> Path:
    return app_data_dir() / "app_blocker.log"

def stop_signal_path() -> Path:
    return app_data_dir() / "focusmode.stop"

def heartbeat_path() -> Path:
    return app_data_dir() / "focusmode.heartbeat"

def hosts_backup_path() -> Path:
    return app_data_dir() / "hosts.backup"

def session_lock_path() -> Path:
    return app_data_dir() / SESSION_LOCK_FILENAME

def log(msg: str) -> None:
    try:
        ts = datetime.now().isoformat(timespec="seconds")
        with log_path().open("a", encoding="utf-8") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass

def info(msg: str) -> None:
    try:
        print(msg)
    except Exception:
        pass
    log(msg)

def warn(msg: str) -> None:
    try:
        print(f"Warning: {msg}")
    except Exception:
        pass
    log(f"Warning: {msg}")

def err(where: str) -> None:
    txt = f"\nERROR in {where}:\n{traceback.format_exc()}"
    try:
        print(txt)
    except Exception:
        pass
    log(txt)


# ============================================================
# SESSION LOCK / HEARTBEAT
# ============================================================

def write_session_lock(worker_pid: int, ui_pid: int | None) -> None:
    try:
        data = {
            "worker_pid": int(worker_pid),
            "ui_pid": int(ui_pid) if ui_pid else 0,
            "started_at": int(time.time()),
        }
        session_lock_path().write_text(json.dumps(data), encoding="utf-8")
    except Exception:
        pass

def read_session_lock() -> dict | None:
    try:
        p = session_lock_path()
        if not p.exists():
            return None
        return json.loads(p.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None

def clear_session_lock() -> None:
    try:
        p = session_lock_path()
        if p.exists():
            p.unlink()
    except Exception:
        pass

def is_heartbeat_fresh(max_age_sec: float = 6.0) -> bool:
    p = heartbeat_path()
    try:
        if not p.exists():
            return False
        txt = p.read_text(encoding="utf-8", errors="ignore").strip()
        t = int(txt)
        return (time.time() - t) <= max_age_sec
    except Exception:
        return False

def write_heartbeat() -> None:
    try:
        heartbeat_path().write_text(str(int(time.time())), encoding="utf-8")
    except Exception:
        pass


# ============================================================
# HOSTS MANAGEMENT (aggressive unblock)
# ============================================================

def hosts_path() -> Path:
    return Path(r"C:\Windows\System32\drivers\etc\hosts")

def backup_hosts_once() -> None:
    try:
        hp = hosts_path()
        bp = hosts_backup_path()
        if not bp.exists():
            shutil.copy2(hp, bp)
            info(f"Backed up hosts -> {bp}")
    except Exception:
        err("backup_hosts_once")

def _normalize_host(h: str) -> str:
    h = (h or "").strip().lower().rstrip(".")
    return h

def _target_domains_set() -> set[str]:
    s = set()
    for d in HOSTS_BLOCK_ENTRIES:
        d = _normalize_host(d)
        if d:
            s.add(d)
    return s

def _host_matches_target(host: str, targets: set[str]) -> bool:
    host = _normalize_host(host)
    if not host:
        return False
    if host in targets:
        return True
    # If targets contains "youtube.com", remove "m.youtube.com", "www.youtube.com", etc.
    for t in targets:
        if host == t:
            return True
        if host.endswith("." + t):
            return True
    return False

def remove_marked_block_section(lines: list[str]) -> list[str]:
    start_markers = {HOSTS_MARK_START, HOSTS_MARK_START_OLD}
    end_markers = {HOSTS_MARK_END}

    out: list[str] = []
    in_block = False
    for raw in lines:
        stripped = raw.strip()
        if stripped in start_markers:
            in_block = True
            continue
        if stripped in end_markers:
            in_block = False
            continue
        if not in_block:
            out.append(raw)
    return out

def remove_all_focus_blocks() -> None:
    """
    Aggressive unblock:
    - Remove marked section (supports old typo marker)
    - Remove any 127.0.0.1 / 0.0.0.0 / ::1 mappings for target domains,
      even if markers are missing/corrupted.
    """
    try:
        hp = hosts_path()
        if not hp.exists():
            return

        text = hp.read_text(encoding="utf-8", errors="ignore")
        lines = text.splitlines()

        # 1) remove our marked block section
        lines = remove_marked_block_section(lines)

        # 2) remove stray blocking entries for our targets
        targets = _target_domains_set()
        cleaned: list[str] = []

        for raw in lines:
            line = raw.rstrip("\n")
            stripped = line.strip()

            if not stripped or stripped.startswith("#"):
                cleaned.append(line)
                continue

            parts = stripped.split()
            if len(parts) < 2:
                cleaned.append(line)
                continue

            ip = parts[0].strip()
            host = parts[1].strip()

            if ip in ("127.0.0.1", "0.0.0.0", "::1") and _host_matches_target(host, targets):
                # drop it
                continue

            cleaned.append(line)

        hp.write_text("\n".join(cleaned).rstrip() + "\n", encoding="utf-8")
        info("Removed all focus blocker hosts entries (aggressive).")
    except Exception:
        err("remove_all_focus_blocks")

def inject_hosts_block(text: str) -> str:
    # Remove any existing marked section first, then append a fresh section
    lines = text.splitlines()
    lines = remove_marked_block_section(lines)
    cleaned = "\n".join(lines).rstrip("\n")

    block_lines = [
        "",
        HOSTS_MARK_START,
        "# This section was added by Study Mode Focus Blocker.",
        "# It will be removed automatically when you stop focus mode.",
    ]
    for d in HOSTS_BLOCK_ENTRIES:
        d = d.strip()
        if not d or d.startswith("#"):
            continue
        block_lines.append(f"127.0.0.1 {d}")
    block_lines.append(HOSTS_MARK_END)

    return cleaned + "\n" + "\n".join(block_lines) + "\n"

def apply_hosts_block() -> None:
    try:
        hp = hosts_path()
        original = hp.read_text(encoding="utf-8", errors="ignore")
        hp.write_text(inject_hosts_block(original), encoding="utf-8")
        info("Hosts blocking section applied.")
        ding_start()
    except Exception:
        err("apply_hosts_block")
        raise

def restore_hosts_from_backup_best_effort() -> None:
    """
    Restore exact backup if present, then ALSO run aggressive removal just in case
    backup was captured when blocked.
    """
    try:
        bp = hosts_backup_path()
        if bp.exists():
            shutil.copy2(bp, hosts_path())
            info("Hosts restored from backup.")
        else:
            warn("No hosts backup found; skipping restore.")
    except Exception:
        err("restore_hosts_from_backup_best_effort")

    # Always do aggressive removal afterwards (guarantees unblock)
    remove_all_focus_blocks()

def flush_dns_cache_best_effort() -> None:
    try:
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True, text=True)
        info("Flushed DNS cache.")
    except Exception:
        pass


# ============================================================
# OPTIONAL: close Discord once (no loop)
# ============================================================

def close_discord_once() -> None:
    if not CLOSE_DISCORD_ON_START:
        return
    try:
        killed_any = False
        for p in psutil.process_iter(["name"]):
            try:
                name = (p.info.get("name") or "")
                if name in DISCORD_PROCESS_NAMES:
                    p.terminate()
                    killed_any = True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        if killed_any:
            time.sleep(1.0)
            for p in psutil.process_iter(["name"]):
                try:
                    name = (p.info.get("name") or "")
                    if name in DISCORD_PROCESS_NAMES:
                        p.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            info("Discord was closed (once).")
    except Exception:
        err("close_discord_once")


# ============================================================
# STARTUP RECOVERY
# ============================================================

def startup_recover_if_needed() -> None:
    """
    If previous run crashed, unblock on startup.
    Conditions:
    - session lock exists but worker PID not alive -> unblock
    - stale heartbeat -> delete
    """
    try:
        lock = read_session_lock()
        if lock:
            wpid = int(lock.get("worker_pid") or 0)
            if wpid <= 0 or not psutil.pid_exists(wpid):
                warn("Detected stale focus session (previous run didn't exit cleanly). Auto-unblocking...")
                # aggressive unblock + dns flush
                remove_all_focus_blocks()
                flush_dns_cache_best_effort()
                clear_session_lock()

        if heartbeat_path().exists() and not is_heartbeat_fresh():
            try:
                heartbeat_path().unlink()
            except Exception:
                pass
    except Exception:
        err("startup_recover_if_needed (non-fatal)")


# ============================================================
# COMBINED WORKER+WATCHER PROCESS
# ============================================================

_CLEANED = False

def cleanup() -> None:
    global _CLEANED
    if _CLEANED:
        return
    _CLEANED = True

    # Ensure unblock, even if backup is bad or markers are broken
    restore_hosts_from_backup_best_effort()
    flush_dns_cache_best_effort()

    # Clear signals/lock/heartbeat
    try:
        if stop_signal_path().exists():
            stop_signal_path().unlink()
    except Exception:
        pass
    try:
        if heartbeat_path().exists():
            heartbeat_path().unlink()
    except Exception:
        pass
    clear_session_lock()
    ding_stop()
    info("FOCUS MODE OFF (cleanup complete).")

def workerwatcher_main(ui_pid: int | None, duration_sec: int | None) -> int:
    """
    One process that:
    - Applies hosts blocks
    - Writes heartbeat + session lock
    - Watches for:
        * stop signal file
        * UI PID dying (unexpected close/crash)
        * optional timer expiring
    Then cleans up and exits.
    """
    global _CLEANED
    _CLEANED = False

    if os.name != "nt":
        info("Windows only.")
        return 1

    if not is_admin():
        info("Worker must be run as Administrator to edit hosts. Exiting.")
        return 2

    # Clear stop signal at start
    try:
        if stop_signal_path().exists():
            stop_signal_path().unlink()
    except Exception:
        pass

    # Register cleanup on normal interpreter exit
    atexit.register(cleanup)

    # Timer
    end_time = None
    if duration_sec and duration_sec > 0:
        end_time = time.time() + float(duration_sec)

    try:
        backup_hosts_once()

        # Apply blocks
        apply_hosts_block()
        close_discord_once()

        # Write lock so startup recovery can detect crashes
        write_session_lock(worker_pid=os.getpid(), ui_pid=ui_pid or 0)

        info("FOCUS MODE ON (worker+watcher active).")
        if end_time is not None:
            mins = max(1, int(round(duration_sec / 60)))
            info(f"Timer enabled: auto-stop after ~{mins} minute(s).")

        last_hb = 0.0
        while True:
            # Stop requested?
            try:
                if stop_signal_path().exists():
                    info("Stop signal detected. Stopping focus mode...")
                    break
            except Exception:
                pass

            # Timer expired?
            if end_time is not None and time.time() >= end_time:
                info("Timer expired. Auto-stopping focus mode...")
                break

            # UI died unexpectedly?
            if ui_pid and ui_pid > 0 and not psutil.pid_exists(ui_pid):
                warn("UI process is gone (closed/crashed). Running cleanup...")
                break

            # Heartbeat
            now = time.time()
            if now - last_hb >= HEARTBEAT_INTERVAL_SEC:
                last_hb = now
                write_heartbeat()

            time.sleep(0.5)

    except Exception:
        err("workerwatcher_main")
    finally:
        try:
            cleanup()
        except Exception:
            pass

    return 0


# ============================================================
# UI
# ============================================================

class FocusUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Study Mode – Focus Blocker (failsafe)")
        self.geometry("720x580")
        self.minsize(720, 580)

        self._worker_proc: subprocess.Popen | None = None
        self._start_time: float | None = None
        self._end_time: float | None = None

        self.log_q = queue.Queue()
        self._tail_stop = threading.Event()
        self._tail_offset = 0

        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self._build_ui()

        threading.Thread(target=self._tail_log, daemon=True).start()
        self._poll_log()
        self._refresh_status()

    def _build_ui(self):
        pad = {"padx": 10, "pady": 8}

        header = ttk.Frame(self)
        header.pack(fill="x", **pad)

        self.status_var = tk.StringVar(value="Status: OFF")
        ttk.Label(header, textvariable=self.status_var, font=("Segoe UI", 12, "bold")).pack(side="left")

        self.timer_var = tk.StringVar(value="")
        ttk.Label(header, textvariable=self.timer_var, font=("Segoe UI", 10)).pack(side="right")

        controls = ttk.Frame(self)
        controls.pack(fill="x", **pad)

        self.start_btn = ttk.Button(controls, text="Start Focus Mode", command=self.start_focus)
        self.start_btn.pack(side="left")

        self.stop_btn = ttk.Button(controls, text="Stop Focus Mode", command=self.stop_focus)
        self.stop_btn.pack(side="left", padx=(10, 0))

        self.restore_btn = ttk.Button(controls, text="Restore Now", command=self.restore_now)
        self.restore_btn.pack(side="left", padx=(10, 0))

        timer_frame = ttk.Frame(self)
        timer_frame.pack(fill="x", **pad)

        ttk.Label(timer_frame, text="Timer (minutes, optional):").pack(side="left")
        self.timer_entry = ttk.Entry(timer_frame, width=10)
        self.timer_entry.pack(side="left", padx=(8, 0))
        ttk.Label(timer_frame, text="Leave blank to run until you stop it.", foreground="gray").pack(
            side="left", padx=(10, 0)
        )

        phrase_frame = ttk.Frame(self)
        phrase_frame.pack(fill="x", **pad)
        ttk.Label(phrase_frame, text=f"To stop, type exactly: {STOP_PHRASE}").pack(anchor="w")
        self.phrase_entry = ttk.Entry(phrase_frame)
        self.phrase_entry.pack(fill="x")

        admin_frame = ttk.Frame(self)
        admin_frame.pack(fill="x", **pad)

        self.admin_var = tk.StringVar(value="")
        ttk.Label(admin_frame, textvariable=self.admin_var, foreground="gray").pack(anchor="w")

        log_frame = ttk.LabelFrame(self, text="Activity Log")
        log_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.log_text = tk.Text(log_frame, height=14, wrap="word")
        self.log_text.pack(fill="both", expand=True, padx=8, pady=8)
        self.log_text.configure(state="disabled")

        ttk.Label(
            self,
            text=f"Files/logs stored in: {app_data_dir()}",
            foreground="gray"
        ).pack(anchor="w", padx=12, pady=(0, 10))

    def _append_log(self, msg: str):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", msg.rstrip() + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _tail_log(self):
        p = log_path()
        try:
            if p.exists():
                self._tail_offset = p.stat().st_size
        except Exception:
            self._tail_offset = 0

        while not self._tail_stop.is_set():
            try:
                if p.exists():
                    size = p.stat().st_size
                    if size < self._tail_offset:
                        self._tail_offset = 0
                    if size > self._tail_offset:
                        with p.open("r", encoding="utf-8", errors="ignore") as f:
                            f.seek(self._tail_offset)
                            chunk = f.read()
                            self._tail_offset = f.tell()
                        for line in chunk.splitlines():
                            if line.strip():
                                self.log_q.put(line)
            except Exception:
                pass
            time.sleep(0.25)

    def _poll_log(self):
        try:
            while True:
                msg = self.log_q.get_nowait()
                self._append_log(msg)
        except queue.Empty:
            pass
        self.after(200, self._poll_log)

    def _worker_running(self) -> bool:
        return self._worker_proc is not None and self._worker_proc.poll() is None

    def _refresh_status(self):
        hb_fresh = is_heartbeat_fresh()
        running = self._worker_running() or hb_fresh

        # self-heal stale heartbeat & stale session lock (UI convenience)
        if heartbeat_path().exists() and not hb_fresh:
            try:
                heartbeat_path().unlink()
            except Exception:
                pass

        lock = read_session_lock()
        if lock:
            wpid = int(lock.get("worker_pid") or 0)
            if wpid and not psutil.pid_exists(wpid):
                # stale lock
                try:
                    clear_session_lock()
                except Exception:
                    pass

        self.status_var.set("Status: ON (Focus Mode Active)" if running else "Status: OFF")
        self.start_btn.configure(state=("disabled" if running else "normal"))
        self.stop_btn.configure(state=("normal" if running else "disabled"))

        self.admin_var.set(
            "Admin: YES (ok)" if is_admin() else "Admin: NO — run this program as Administrator to start focus mode."
        )

        if running and self._start_time is not None:
            if self._end_time is not None:
                remaining = int(self._end_time - time.time())
                remaining = max(0, remaining)
                self.timer_var.set(f"Remaining: {remaining//60:02d}:{remaining%60:02d}")
            else:
                elapsed = int(time.time() - self._start_time)
                self.timer_var.set(f"Running: {elapsed//60:02d}:{elapsed%60:02d}")
        else:
            self.timer_var.set("")
            self._start_time = None
            self._end_time = None

        self.after(500, self._refresh_status)

    def _parse_timer_minutes(self) -> int | None:
        raw = (self.timer_entry.get() or "").strip()
        if not raw:
            return None
        try:
            minutes = float(raw)
        except ValueError:
            messagebox.showwarning("Invalid timer", "Timer must be a number of minutes (e.g., 25). Or leave blank.")
            return None
        if minutes <= 0:
            messagebox.showwarning("Invalid timer", "Timer must be > 0 minutes, or leave blank.")
            return None
        return int(round(minutes * 60))

    def _build_worker_cmd(self, duration_sec: int | None) -> list[str]:
        base_args = ["--workwatch", "--ui-pid", str(os.getpid())]
        if duration_sec:
            base_args += ["--duration-sec", str(duration_sec)]

        if getattr(sys, "frozen", False):
            return [sys.executable] + base_args
        else:
            return [sys.executable, str(Path(__file__).resolve())] + base_args

    def start_focus(self):
        if self._worker_running() or is_heartbeat_fresh():
            return

        if not is_admin():
            messagebox.showwarning(
                "Administrator required",
                "To start focus mode, run this program as Administrator.\n\n"
                "Right-click the .py/.exe and choose 'Run as administrator'."
            )
            return

        # clear stop
        try:
            if stop_signal_path().exists():
                stop_signal_path().unlink()
        except Exception:
            pass

        duration_sec = self._parse_timer_minutes()
        if (self.timer_entry.get() or "").strip() and duration_sec is None:
            return

        cmd = self._build_worker_cmd(duration_sec)
        self._append_log("Starting focus mode..." + (" (timer enabled)" if duration_sec else ""))

        try:
            self._worker_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=str(app_data_dir()),
            )
            write_session_lock(worker_pid=self._worker_proc.pid, ui_pid=os.getpid())
            self._start_time = time.time()
            self._end_time = (self._start_time + duration_sec) if duration_sec else None
            info("UI started worker+watcher.")
        except Exception as e:
            self._append_log(f"Failed to start worker: {e}")
            self._worker_proc = None

    def _stop_phrase_ok(self) -> bool:
        return self.phrase_entry.get().strip() == STOP_PHRASE

    def stop_focus(self):
        if not (self._worker_running() or is_heartbeat_fresh()):
            return

        if REQUIRE_STOP_PHRASE and not self._stop_phrase_ok():
            messagebox.showwarning("Stop blocked", f"Type the full stop phrase exactly:\n\n{STOP_PHRASE}")
            return

        if not messagebox.askyesno("Stop Focus Mode", "Turn OFF Focus Mode and restore normal browsing?"):
            return

        try:
            stop_signal_path().write_text("stop", encoding="utf-8")
        except Exception as e:
            self._append_log(f"Failed to write stop signal: {e}")

        self._append_log("Stop requested. Waiting for cleanup...")
        self.phrase_entry.delete(0, "end")

    def restore_now(self):
        if messagebox.askyesno("Restore", "Force unblock now (aggressive) and flush DNS?"):
            try:
                try:
                    stop_signal_path().write_text("stop", encoding="utf-8")
                except Exception:
                    pass
                restore_hosts_from_backup_best_effort()
                flush_dns_cache_best_effort()
                clear_session_lock()
                self._append_log("Restore/unblock complete.")
            except Exception as e:
                self._append_log(f"Restore failed: {e}")

    def on_close(self):
        # If focus is on, request stop
        if self._worker_running() or is_heartbeat_fresh():
            if not messagebox.askyesno(
                "Stop Focus Mode?",
                "Focus Mode is ON.\n\nClosing will STOP focus mode and restore browsing.\n\nStop and close?"
            ):
                return
            try:
                stop_signal_path().write_text("stop", encoding="utf-8")
            except Exception:
                pass

            deadline = time.time() + 10
            while is_heartbeat_fresh() and time.time() < deadline:
                self.update()
                time.sleep(0.2)

        self._tail_stop.set()
        self.destroy()


# ============================================================
# ARG PARSING / ENTRYPOINT
# ============================================================

def parse_args(argv: list[str]) -> dict:
    out = {"mode": "ui", "ui_pid": None, "duration_sec": None}

    if "--workwatch" in argv:
        out["mode"] = "workwatch"
    if "--restore" in argv:
        out["mode"] = "restore"

    if "--ui-pid" in argv:
        try:
            i = argv.index("--ui-pid")
            out["ui_pid"] = int(argv[i + 1])
        except Exception:
            out["ui_pid"] = None

    if "--duration-sec" in argv:
        try:
            i = argv.index("--duration-sec")
            out["duration_sec"] = int(float(argv[i + 1]))
        except Exception:
            out["duration_sec"] = None

    return out

def restore_only() -> int:
    try:
        info("Manual restore requested (aggressive unblock).")
        restore_hosts_from_backup_best_effort()
        flush_dns_cache_best_effort()
        clear_session_lock()
        info("Restore complete.")
        return 0
    except Exception:
        err("restore_only")
        return 1

def main():
    args = parse_args(sys.argv[1:])

    if args["mode"] == "restore":
        sys.exit(restore_only())

    if args["mode"] == "workwatch":
        sys.exit(workerwatcher_main(args.get("ui_pid"), args.get("duration_sec")))

    # UI mode
    try:
        info(f"UI started. Artifacts in: {app_data_dir()}")
        startup_recover_if_needed()
        app = FocusUI()
        app.mainloop()
    except Exception:
        err("UI mainloop")
        sys.exit(1)

if __name__ == "__main__":
    main()
