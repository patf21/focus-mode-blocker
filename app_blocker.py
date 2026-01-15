"""
Study Mode – Focus Blocker (Windows)

Key features:
- UI + Worker architecture (worker does blocking & cleanup; UI controls it)
- Optional timer (minutes) in UI. Blank = run until stopped. Number = auto-stop.
- Auto-elevate the WORKER via UAC if UI is not admin (so Git Bash/admin issues go away)
- Firefox OPTIONAL:
    - If Firefox is installed: uses Firefox enterprise policy (policies.json) + clears Firefox site data + restarts Firefox.
    - If Firefox is NOT installed: runs HOSTS-ONLY mode (still blocks system-wide via hosts) + Discord kill loop.
- Safe cleanup on stop / UI close / UI killed (worker watches parent PID)
- Logs to app_blocker.log; UI tails this log so you still see activity even when worker is elevated (no stdout pipe).

Run:
- python app_blocker.py          (UI)
- python app_blocker.py --worker --parent-pid <PID> [--duration-sec <seconds>]
- python app_blocker.py --restore (manual cleanup if you ever hard-kill everything)
"""

import atexit
import ctypes
import json
import os
import shutil
import subprocess
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path

import psutil

# pywin32
import win32con
import win32gui

# UI
import threading
import queue
import tkinter as tk
from tkinter import ttk, messagebox


# ============================================================
# CONFIG
# ============================================================

STOP_PHRASE = "The quick brown fox jumps over the lazy dog"
REQUIRE_STOP_PHRASE = True

BLOCKED_DOMAINS = [
    # YouTube
    "youtube.com", "www.youtube.com", "m.youtube.com", "music.youtube.com",
    "studio.youtube.com", "kids.youtube.com",
    "accounts.youtube.com", "apis.google.com",
    "*.youtube.com", "youtu.be", "*.youtu.be",

    # Google redirect / consent / auth pages
    "consent.google.com", "www.google.com", "accounts.google.com",

    # Video delivery / assets
    "googlevideo.com", "*.googlevideo.com",
    "ytimg.com", "*.ytimg.com",
    "youtubei.googleapis.com", "youtube.googleapis.com",

    # Discord
    "discord.com", "www.discord.com", "*.discord.com",
    "discord.gg", "*.discord.gg",

    # Instagram
    "instagram.com", "www.instagram.com", "*.instagram.com",

    # Reddit
    "reddit.com", "www.reddit.com", "*.reddit.com",
    "old.reddit.com", "new.reddit.com",
    "redd.it", "*.redd.it",

    # LinkedIn
    "linkedin.com", "www.linkedin.com", "*.linkedin.com",
    "lnkd.in",
]

HOSTS_BLOCK_ENTRIES = [
    # YouTube
    "youtube.com",
    "www.youtube.com",
    "m.youtube.com",
    "youtu.be",
    "googlevideo.com",
    "ytimg.com",

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

SITE_DATA_DOMAINS = [
    "youtube.com", "googlevideo.com", "ytimg.com",
    "discord.com", "discord.gg",
    "instagram.com",
    "reddit.com", "redd.it",
    "linkedin.com",
]

KILL_DISCORD_APP = True
BLOCKED_PROCESSES = {"Discord.exe"}

MARKER_NO_ORIGINAL = "__NO_ORIGINAL_FILE__"

AUTO_RESTART_FIREFOX = True
FIREFOX_CLOSE_TIMEOUT_SEC = 15

RESET_HOSTS_ON_EXIT = True
RESET_HOSTS_ON_START = False  # WARNING: can wipe custom hosts entries.

HOSTS_DEFAULT_CONTENT = r"""# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address and the host name
# should be separated by at least one space.
#
# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost
"""

FAIL_FAST_ON_CRITICAL_ERRORS = True
HEARTBEAT_INTERVAL_SEC = 2.0


# ============================================================
# ADMIN / CONSOLE ENCODING HELPERS
# ============================================================

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def relaunch_elevated(cmd: list[str]) -> bool:
    """
    Launch cmd with UAC prompt.
    Returns True if ShellExecute appears successful.
    """
    try:
        exe = cmd[0]
        params = " ".join(f'"{a}"' if " " in a else a for a in cmd[1:])
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        return rc > 32
    except Exception:
        return False

def force_utf8_stdout_best_effort():
    # Avoid UnicodeEncodeError on some Windows console streams.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# ============================================================
# LOGGING
# ============================================================

def app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent

def _default_log_path() -> Path:
    return app_dir() / "app_blocker.log"

def log(msg: str) -> None:
    try:
        p = _default_log_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().isoformat(timespec="seconds")
        with p.open("a", encoding="utf-8") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass

def print_exc(where: str) -> None:
    txt = f"\nERROR in {where}:\n{traceback.format_exc()}"
    try:
        print(txt)
    except Exception:
        pass
    log(txt)

def print_warn(msg: str) -> None:
    txt = f"Warning: {msg}"
    try:
        print(txt)
    except Exception:
        pass
    log(txt)

def print_info(msg: str) -> None:
    try:
        print(msg)
    except Exception:
        pass
    log(msg)


# ============================================================
# PATHS / SIGNALS
# ============================================================

def ensure_dir(p: Path) -> None:
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        print_exc(f"ensure_dir({p})")
        if FAIL_FAST_ON_CRITICAL_ERRORS:
            raise

def hosts_path() -> Path:
    return Path(r"C:\Windows\System32\drivers\etc\hosts")

def hosts_backup_path() -> Path:
    return app_dir() / "hosts.focus_backup"

def stop_signal_path() -> Path:
    return app_dir() / "focusmode.stop"

def heartbeat_path() -> Path:
    return app_dir() / "focusmode.heartbeat"


# ============================================================
# FIREFOX (OPTIONAL)
# ============================================================

def firefox_exe_path(optional: bool = True) -> Path | None:
    candidates = [
        Path(r"C:\Program Files\Mozilla Firefox\firefox.exe"),
        Path(r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe"),
    ]
    for p in candidates:
        if p.exists():
            return p
    if optional:
        return None
    raise FileNotFoundError(
        "Desktop Firefox not found in Program Files. Install Firefox from mozilla.org (not the Microsoft Store)."
    )

def firefox_policies_path(fx: Path) -> Path:
    return fx.parent / "distribution" / "policies.json"

def backup_path(policies_path: Path) -> Path:
    return policies_path.with_name("policies.json.focus_backup")


# ============================================================
# HOSTS (BACKUP + APPLY + RESET)
# ============================================================

def backup_hosts() -> None:
    try:
        hp = hosts_path()
        bp = hosts_backup_path()
        if not bp.exists():
            shutil.copy2(hp, bp)
            print_info(f"Backed up hosts -> {bp}")
    except Exception:
        print_exc("backup_hosts (non-fatal)")

def reset_hosts_to_default() -> None:
    try:
        hp = hosts_path()
        hp.write_text(HOSTS_DEFAULT_CONTENT, encoding="utf-8")
        print_info("Hosts file reset to default")
    except Exception:
        print_exc("reset_hosts_to_default")
        if FAIL_FAST_ON_CRITICAL_ERRORS:
            raise

def apply_hosts_block() -> None:
    try:
        hp = hosts_path()
        text = hp.read_text(encoding="utf-8", errors="ignore")
        lines = text.splitlines()
        existing = set(l.strip() for l in lines)

        new_lines = []
        for d in HOSTS_BLOCK_ENTRIES:
            entry = f"127.0.0.1 {d}"
            if entry not in existing:
                new_lines.append(entry)

        if new_lines:
            lines.append("")
            lines.append("# --- app_blocker focus mode ---")
            lines.extend(new_lines)

        hp.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print_info("Hosts blocking applied")
    except Exception:
        print_exc("apply_hosts_block")
        raise


# ============================================================
# FIREFOX PROFILE / SITE DATA CLEAR (OPTIONAL)
# ============================================================

def firefox_default_profile_path() -> Path:
    appdata = os.environ.get("APPDATA")
    if not appdata:
        raise RuntimeError("APPDATA env var not found; cannot locate Firefox profile.")

    profiles_ini = Path(appdata) / "Mozilla" / "Firefox" / "profiles.ini"
    if not profiles_ini.exists():
        raise RuntimeError(f"profiles.ini not found at: {profiles_ini}")

    text = profiles_ini.read_text(encoding="utf-8", errors="ignore")

    current: dict[str, str] = {}
    in_profile = False
    chosen_path: str | None = None
    chosen_is_relative = True

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue

        if line.startswith("[Profile"):
            current = {}
            in_profile = True
            continue

        if not in_profile:
            continue

        if line.startswith("[") and line.endswith("]") and not line.startswith("[Profile"):
            in_profile = False
            continue

        if "=" in line:
            k, v = line.split("=", 1)
            current[k.strip()] = v.strip()

            if current.get("Default") == "1" and "Path" in current:
                chosen_path = current["Path"]
                chosen_is_relative = (current.get("IsRelative", "1") == "1")

    if not chosen_path:
        raise RuntimeError("Could not find Default=1 profile in profiles.ini.")

    base = Path(appdata) / "Mozilla" / "Firefox"
    return (base / chosen_path) if chosen_is_relative else Path(chosen_path)

def clear_firefox_site_data(profile_path: Path, domains: list[str]) -> None:
    try:
        storage_default = profile_path / "storage" / "default"
        if not storage_default.exists():
            return

        needles = []
        for d in domains:
            d = d.lower().strip()
            if d:
                needles.append(d.replace(".", "+"))

        for entry in storage_default.iterdir():
            name = entry.name.lower()
            if any(n in name for n in needles):
                try:
                    if entry.is_dir():
                        shutil.rmtree(entry, ignore_errors=True)
                    else:
                        try:
                            entry.unlink()
                        except FileNotFoundError:
                            pass
                except Exception:
                    print_exc(f"clear_firefox_site_data removing {entry} (non-fatal)")
    except Exception:
        print_exc("clear_firefox_site_data (non-fatal)")


# ============================================================
# POLICIES BACKUP / RESTORE / WRITE (OPTIONAL)
# ============================================================

def backup_existing(policies_path: Path) -> None:
    try:
        bkp = backup_path(policies_path)
        ensure_dir(policies_path)

        if policies_path.exists():
            shutil.copy2(policies_path, bkp)
            print_info(f"Backed up policies.json -> {bkp}")
        else:
            bkp.write_text(MARKER_NO_ORIGINAL, encoding="utf-8")
            print_info(f"No original policies.json; wrote marker backup -> {bkp}")
    except Exception:
        print_exc("backup_existing")
        if FAIL_FAST_ON_CRITICAL_ERRORS:
            raise

def restore_from_backup(policies_path: Path) -> bool:
    try:
        bkp = backup_path(policies_path)
        if not bkp.exists():
            return False

        content = bkp.read_text(encoding="utf-8", errors="ignore").strip()
        if content == MARKER_NO_ORIGINAL:
            try:
                if policies_path.exists():
                    policies_path.unlink()
            except Exception:
                pass
        else:
            shutil.copy2(bkp, policies_path)

        try:
            bkp.unlink()
        except Exception:
            pass

        return True
    except Exception:
        print_exc("restore_from_backup")
        return False

def write_policy(policies_path: Path) -> None:
    try:
        policy_obj = {"policies": {"WebsiteFilter": {"Block": BLOCKED_DOMAINS}}}
        policies_path.parent.mkdir(parents=True, exist_ok=True)

        tmp = policies_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(policy_obj, indent=2), encoding="utf-8")
        tmp.replace(policies_path)

        print_info(f"Wrote Firefox policy: {policies_path}")
    except Exception:
        print_exc("write_policy")
        if FAIL_FAST_ON_CRITICAL_ERRORS:
            raise


# ============================================================
# FIREFOX PROCESS CONTROL (OPTIONAL)
# ============================================================

def _enum_firefox_windows() -> list[int]:
    result: list[int] = []

    def cb(hwnd, _):
        try:
            if win32gui.IsWindowVisible(hwnd):
                cls = win32gui.GetClassName(hwnd)
                if cls == "MozillaWindowClass":
                    result.append(hwnd)
        except Exception:
            pass
        return True

    try:
        win32gui.EnumWindows(cb, None)
    except Exception:
        pass

    return result

def is_firefox_running() -> bool:
    try:
        for p in psutil.process_iter(["name"]):
            try:
                if (p.info["name"] or "").lower() == "firefox.exe":
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return False
    except Exception:
        return False

def hard_kill_firefox() -> None:
    try:
        for p in psutil.process_iter(["name"]):
            try:
                if (p.info["name"] or "").lower() == "firefox.exe":
                    p.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            except Exception:
                pass
    except Exception:
        pass

def close_firefox_gracefully(timeout_sec: int = FIREFOX_CLOSE_TIMEOUT_SEC) -> None:
    for hwnd in _enum_firefox_windows():
        try:
            win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
        except Exception:
            pass

    start = time.time()
    while is_firefox_running() and (time.time() - start) < timeout_sec:
        time.sleep(0.2)

    if is_firefox_running():
        for p in psutil.process_iter(["name"]):
            try:
                if (p.info["name"] or "").lower() == "firefox.exe":
                    p.terminate()
            except Exception:
                pass

        start = time.time()
        while is_firefox_running() and (time.time() - start) < 5:
            time.sleep(0.2)

    if is_firefox_running():
        hard_kill_firefox()
        time.sleep(0.5)

def wait_for_firefox_exit(timeout=10) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if not is_firefox_running():
            return True
        time.sleep(0.2)
    return False

def launch_firefox(fx: Path) -> None:
    try:
        subprocess.Popen([str(fx)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print_info(f"Launching Firefox EXE: {fx}")
    except Exception:
        print_exc("launch_firefox")
        if FAIL_FAST_ON_CRITICAL_ERRORS:
            raise

def verify_firefox_binary(expected: Path, timeout_sec: float = 6.0) -> None:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        for p in psutil.process_iter(["name", "exe"]):
            try:
                if (p.info["name"] or "").lower() == "firefox.exe":
                    exe = p.info.get("exe")
                    if exe:
                        running = Path(exe)
                        print_info(f"Firefox running from: {running}")
                        if running.resolve() != expected.resolve():
                            print_warn("Running Firefox is NOT the expected EXE (policies may be ignored).")
                        return
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            except Exception:
                pass
        time.sleep(0.2)

    print_warn("Could not verify Firefox process path (no firefox.exe process found).")


# ============================================================
# DISCORD KILL
# ============================================================

def kill_discord() -> None:
    if not KILL_DISCORD_APP:
        return
    for p in psutil.process_iter(["name"]):
        try:
            if p.info["name"] in BLOCKED_PROCESSES:
                p.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception:
            pass


# ============================================================
# CLEANUP / RECOVERY
# ============================================================

_POLICIES_PATH: Path | None = None
_CLEANED = False
_FX_EXE: Path | None = None  # remember if we had Firefox

def _close_and_clear_site_data_best_effort() -> None:
    try:
        close_firefox_gracefully()
    except Exception:
        print_exc("close_firefox_gracefully (non-fatal)")

    try:
        hard_kill_firefox()
        time.sleep(0.5)
    except Exception:
        pass

    try:
        profile = firefox_default_profile_path()
        clear_firefox_site_data(profile, SITE_DATA_DOMAINS)
    except Exception:
        print_exc("firefox_default_profile_path/clear_firefox_site_data (non-fatal)")

def cleanup_and_optionally_restart() -> None:
    global _POLICIES_PATH, _CLEANED, _FX_EXE
    if _CLEANED:
        return
    _CLEANED = True

    # Firefox cleanup (only if Firefox exists/was used)
    if _FX_EXE is not None:
        _close_and_clear_site_data_best_effort()
        wait_for_firefox_exit()

        if _POLICIES_PATH is not None:
            try:
                restored = restore_from_backup(_POLICIES_PATH)
                if restored:
                    print_info("Restored Firefox policies.json to original state.")
                else:
                    print_info("No Firefox policy backup found to restore (nothing to do).")
            except Exception:
                print_exc("cleanup.restore_from_backup (non-fatal)")

    # Reset hosts
    if RESET_HOSTS_ON_EXIT:
        try:
            reset_hosts_to_default()
            print_info("Reset hosts file to Windows default.")
        except Exception:
            print_exc("cleanup.reset_hosts_to_default (non-fatal)")

    # Restart Firefox unblocked
    if AUTO_RESTART_FIREFOX and _FX_EXE is not None:
        try:
            print_info("Restarting Firefox so the unblocked state takes effect...")
            launch_firefox(_FX_EXE)
            verify_firefox_binary(_FX_EXE)
        except Exception:
            print_exc("cleanup.launch_firefox (non-fatal)")

def safe_recover_if_needed() -> None:
    """
    Best-effort recovery if previous run was interrupted.
    - If Firefox exists, restore policy backup if present.
    - Optionally reset hosts at startup (disabled by default).
    """
    fx = firefox_exe_path(optional=True)
    if fx is not None:
        try:
            pp = firefox_policies_path(fx)
            if restore_from_backup(pp):
                print_info("Startup recovery: restored original Firefox policies from backup.")
        except Exception:
            print_exc("safe_recover_if_needed (non-fatal)")

    if RESET_HOSTS_ON_START:
        try:
            reset_hosts_to_default()
            print_info("Startup recovery: reset hosts to default (enabled).")
        except Exception:
            print_exc("safe_recover_hosts (non-fatal)")


# ============================================================
# WORKER PROCESS (does blocking + watchdog + optional timer)
# ============================================================

def _pid_alive(pid: int) -> bool:
    try:
        if pid <= 0:
            return False
        return psutil.pid_exists(pid)
    except Exception:
        return False

def worker_main(parent_pid: int | None, duration_sec: int | None) -> int:
    """
    Runs focus mode and watches for:
      - stop signal file
      - parent PID dying (Task Manager kill of UI)
      - optional duration timer expiring (auto-stop)
    On any event, runs cleanup and exits.
    """
    force_utf8_stdout_best_effort()

    global _POLICIES_PATH, _CLEANED, _FX_EXE
    _CLEANED = False

    end_time: float | None = None
    if duration_sec is not None and duration_sec > 0:
        end_time = time.time() + float(duration_sec)

    try:
        if os.name != "nt":
            print_info("Windows only.")
            return 1

        # Recovery in case last run died
        safe_recover_if_needed()

        # Clear any stale stop signal
        try:
            sp = stop_signal_path()
            if sp.exists():
                sp.unlink()
        except Exception:
            pass

        # Determine Firefox availability (optional)
        fx = firefox_exe_path(optional=True)
        _FX_EXE = fx

        if fx is None:
            print_warn("Firefox not found. Running in HOSTS-ONLY mode (system-wide hosts blocking still applies).")
        else:
            print_info(f"Firefox detected: {fx}")

        # Apply hosts blocks (system-wide)
        backup_hosts()
        apply_hosts_block()

        # If enabled, this wipes hosts (generally leave disabled)
        if RESET_HOSTS_ON_START:
            reset_hosts_to_default()
            print_info("Reset hosts file to default at startup (enabled).")

        # Firefox policies (only if Firefox exists)
        if fx is not None:
            policies_path = firefox_policies_path(fx)
            _POLICIES_PATH = policies_path

            # If prior run crashed, recover first
            if restore_from_backup(policies_path):
                print_info("Recovered from previous interrupted run (restored original policies).")

            # Ensure Firefox is closed before enabling policy
            _close_and_clear_site_data_best_effort()

            backup_existing(policies_path)
            write_policy(policies_path)

        # Ensure cleanup on normal exit signals (won't run on hard-kill)
        atexit.register(cleanup_and_optionally_restart)

        print_info("FOCUS MODE ON (worker active)")
        print_info("Worker will stop if UI requests stop, UI process is killed, or timer expires.")

        if end_time is not None:
            mins = max(1, int(round(duration_sec / 60)))
            print_info(f"Timer enabled: auto-stop after ~{mins} minute(s).")

        if AUTO_RESTART_FIREFOX and fx is not None:
            launch_firefox(fx)
            verify_firefox_binary(fx)

        last_hb = 0.0
        while True:
            # Discord kill loop
            try:
                kill_discord()
            except Exception:
                pass

            # Stop requested?
            try:
                if stop_signal_path().exists():
                    print_info("Stop signal detected. Stopping focus mode...")
                    break
            except Exception:
                pass

            # Timer expired?
            if end_time is not None and time.time() >= end_time:
                print_info("Timer expired. Auto-stopping focus mode...")
                break

            # Parent died? (e.g., UI killed in Task Manager)
            if parent_pid is not None and parent_pid > 0:
                if not _pid_alive(parent_pid):
                    print_warn("UI process is gone (likely Task Manager close). Running cleanup...")
                    break

            # Heartbeat
            now = time.time()
            if now - last_hb >= HEARTBEAT_INTERVAL_SEC:
                last_hb = now
                try:
                    heartbeat_path().write_text(str(int(now)), encoding="utf-8")
                except Exception:
                    pass

            time.sleep(1)

    except Exception:
        print("\nWORKER FATAL ERROR — ABORTING")
        traceback.print_exc()
        log("WORKER FATAL:\n" + traceback.format_exc())
    finally:
        try:
            cleanup_and_optionally_restart()
        except Exception:
            pass

        # best-effort cleanup artifacts
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

    print_info("FOCUS MODE OFF (worker exited).")
    return 0


# ============================================================
# UI PROCESS
# ============================================================

class FocusUI(tk.Tk):
    def __init__(self):
        super().__init__()
        force_utf8_stdout_best_effort()

        self.title("Study Mode – Focus Blocker")
        self.geometry("700x560")
        self.minsize(700, 560)

        self.log_q = queue.Queue()
        self._worker_proc: subprocess.Popen | None = None
        self._start_time: float | None = None
        self._end_time: float | None = None

        self._tail_stop = threading.Event()
        self._tail_offset = 0

        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self._build_ui()

        # Tail log file so UI shows activity even when worker is elevated (no stdout pipe).
        threading.Thread(target=self._tail_log_file, daemon=True).start()

        self._poll_worker_output()
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

        log_frame = ttk.LabelFrame(self, text="Activity Log")
        log_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.log_text = tk.Text(log_frame, height=14, wrap="word")
        self.log_text.pack(fill="both", expand=True, padx=8, pady=8)
        self.log_text.configure(state="disabled")

        ttk.Label(
            self,
            text="Tip: Worker needs Administrator to modify hosts and Firefox policies. If needed, it will prompt UAC.",
            foreground="gray"
        ).pack(anchor="w", padx=12, pady=(0, 10))

    def _append_log(self, msg: str):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", msg.rstrip() + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _worker_running(self) -> bool:
        return self._worker_proc is not None and self._worker_proc.poll() is None

    def _refresh_status(self):
        running = self._worker_running()
        # If we launched elevated via UAC, we won't have a Popen handle;
        # In that case, infer running from heartbeat file presence.
        hb_exists = heartbeat_path().exists()
        inferred_running = running or hb_exists

        self.status_var.set("Status: ON (Focus Mode Active)" if inferred_running else "Status: OFF")
        self.start_btn.configure(state=("disabled" if inferred_running else "normal"))
        self.stop_btn.configure(state=("normal" if inferred_running else "disabled"))

        if inferred_running and self._start_time is not None:
            if self._end_time is not None:
                remaining = int(self._end_time - time.time())
                if remaining < 0:
                    remaining = 0
                self.timer_var.set(f"Remaining: {remaining//60:02d}:{remaining%60:02d}")
            else:
                elapsed = int(time.time() - self._start_time)
                self.timer_var.set(f"Running: {elapsed//60:02d}:{elapsed%60:02d}")
        else:
            self.timer_var.set("")
            self._start_time = None
            self._end_time = None

        self.after(500, self._refresh_status)

    def _poll_worker_output(self):
        # Drain queued output from worker stdout thread (only when non-elevated Popen is used)
        try:
            while True:
                msg = self.log_q.get_nowait()
                self._append_log(msg)
        except queue.Empty:
            pass
        self.after(200, self._poll_worker_output)

    def _tail_log_file(self):
        """
        Tail app_blocker.log and stream to UI.
        Works even when worker is elevated (no stdout pipe).
        """
        p = _default_log_path()
        # Start tail at end to avoid dumping huge history
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
                        # log rotated/truncated
                        self._tail_offset = 0
                    if size > self._tail_offset:
                        with p.open("r", encoding="utf-8", errors="ignore") as f:
                            f.seek(self._tail_offset)
                            chunk = f.read()
                            self._tail_offset = f.tell()

                        # Push new lines into the UI thread via queue
                        for line in chunk.splitlines():
                            if line.strip():
                                self.log_q.put(line)
            except Exception:
                pass

            time.sleep(0.25)

    def _parse_timer_minutes(self) -> int | None:
        """
        Returns:
          None -> no timer (run indefinitely)
          int  -> duration in seconds
        """
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
        base_args = ["--worker", "--parent-pid", str(os.getpid())]
        if duration_sec:
            base_args += ["--duration-sec", str(duration_sec)]

        if getattr(sys, "frozen", False):
            return [sys.executable] + base_args
        else:
            return [sys.executable, str(Path(__file__).resolve())] + base_args

    def start_focus(self):
        # avoid double-start
        if self._worker_running() or heartbeat_path().exists():
            return

        # Clear stop signal
        try:
            sp = stop_signal_path()
            if sp.exists():
                sp.unlink()
        except Exception:
            pass

        duration_sec = self._parse_timer_minutes()
        if (self.timer_entry.get() or "").strip() and duration_sec is None:
            return

        worker_cmd = self._build_worker_cmd(duration_sec)

        self._append_log("Starting focus mode worker..." + (" (timer enabled)" if duration_sec else ""))

        # Worker needs admin to edit hosts (and Firefox policies if present)
        if not is_admin():
            ok = relaunch_elevated(worker_cmd)
            if ok:
                self._append_log("Worker launched as Administrator (UAC).")
                self._start_time = time.time()
                self._end_time = (self._start_time + duration_sec) if duration_sec else None
                # No Popen handle in elevated path; log tail will show activity.
                self._worker_proc = None
                return
            else:
                self._append_log("Failed to elevate worker. Try running this app as Administrator.")
                return

        # Already admin: launch and capture stdout
        try:
            self._worker_proc = subprocess.Popen(
                worker_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            self._start_time = time.time()
            self._end_time = (self._start_time + duration_sec) if duration_sec else None
            threading.Thread(target=self._read_worker_stdout, daemon=True).start()
        except Exception as e:
            self._append_log(f"Failed to start worker: {e}")
            self._worker_proc = None
            self._start_time = None
            self._end_time = None

    def _read_worker_stdout(self):
        try:
            if not self._worker_proc or not self._worker_proc.stdout:
                return
            for line in self._worker_proc.stdout:
                if line.strip():
                    self.log_q.put(line.rstrip())
        except Exception as e:
            self.log_q.put(f"(UI) Worker output read error: {e}")

    def _stop_phrase_ok(self) -> bool:
        return self.phrase_entry.get().strip() == STOP_PHRASE

    def stop_focus(self):
        if not (self._worker_running() or heartbeat_path().exists()):
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

        self._append_log("Stop requested. Waiting for worker to exit...")
        self.phrase_entry.delete(0, "end")

    def on_close(self):
        if self._worker_running() or heartbeat_path().exists():
            if not messagebox.askyesno(
                "Stop Focus Mode?",
                "Focus Mode is ON.\n\nClosing will STOP focus mode and restore browsing.\n\nStop and close?"
            ):
                return

            try:
                stop_signal_path().write_text("stop", encoding="utf-8")
            except Exception as e:
                self._append_log(f"Failed to write stop signal: {e}")

            self._append_log("Close requested. Waiting for worker cleanup...")

            deadline = time.time() + 20
            while heartbeat_path().exists() and time.time() < deadline:
                self.update()
                time.sleep(0.2)

            if heartbeat_path().exists():
                self._append_log("Worker still running; closing UI anyway (worker should still cleanup shortly).")

        self._tail_stop.set()
        self.destroy()


# ============================================================
# ENTRYPOINT + ARG PARSING
# ============================================================

def parse_args(argv: list[str]) -> dict:
    out = {"mode": "ui", "parent_pid": None, "duration_sec": None}
    if "--worker" in argv:
        out["mode"] = "worker"
    if "--restore" in argv:
        out["mode"] = "restore"

    if "--parent-pid" in argv:
        try:
            i = argv.index("--parent-pid")
            out["parent_pid"] = int(argv[i + 1])
        except Exception:
            out["parent_pid"] = None

    if "--duration-sec" in argv:
        try:
            i = argv.index("--duration-sec")
            out["duration_sec"] = int(float(argv[i + 1]))
        except Exception:
            out["duration_sec"] = None

    return out

def restore_only() -> int:
    """
    Manual restore mode:
      python app_blocker.py --restore
    Useful if you ever hard-kill BOTH processes and need cleanup.
    """
    force_utf8_stdout_best_effort()
    try:
        fx = firefox_exe_path(optional=True)
        global _POLICIES_PATH, _CLEANED, _FX_EXE
        _CLEANED = False
        _FX_EXE = fx
        if fx is not None:
            _POLICIES_PATH = firefox_policies_path(fx)
        else:
            _POLICIES_PATH = None
        cleanup_and_optionally_restart()
        print_info("Restore complete.")
        return 0
    except Exception:
        print_exc("restore_only")
        return 1

def main():
    args = parse_args(sys.argv[1:])

    if args["mode"] == "restore":
        sys.exit(restore_only())

    if args["mode"] == "worker":
        parent_pid = args.get("parent_pid")
        duration_sec = args.get("duration_sec")
        sys.exit(worker_main(parent_pid, duration_sec))

    # UI mode
    try:
        app = FocusUI()
        app.mainloop()
    except Exception:
        print("\nUI FATAL ERROR — PROGRAM ABORTED")
        traceback.print_exc()
        log("UI FATAL:\n" + traceback.format_exc())
        if getattr(sys, "frozen", False):
            input("\nPress ENTER to exit...")
        sys.exit(1)


if __name__ == "__main__":
    main()
