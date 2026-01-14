import atexit
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

# ---------------------------
# UI imports (only used in UI mode)
# ---------------------------
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
    # YouTube
    "youtube.com",
    "googlevideo.com",
    "ytimg.com",

    # Discord
    "discord.com",
    "discord.gg",

    # Instagram
    "instagram.com",

    # Reddit
    "reddit.com",
    "redd.it",

    # LinkedIn
    "linkedin.com",
]


KILL_DISCORD_APP = True
BLOCKED_PROCESSES = {"Discord.exe"}

MARKER_NO_ORIGINAL = "__NO_ORIGINAL_FILE__"

AUTO_RESTART_FIREFOX = True
FIREFOX_CLOSE_TIMEOUT_SEC = 15

RESET_HOSTS_ON_EXIT = True
RESET_HOSTS_ON_START = False

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

# Worker will also periodically write a "heartbeat" so UI can show alive status
HEARTBEAT_INTERVAL_SEC = 2.0


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
    txt = f"\n ERROR in {where}:\n{traceback.format_exc()}"
    print(txt)
    log(txt)

def print_warn(msg: str) -> None:
    txt = f"\n Warning  {msg}"
    print(txt)
    log(txt)

def print_info(msg: str) -> None:
    print(msg)
    log(msg)


# ============================================================
# PATHS / FIREFOX DISCOVERY (FORCE DESKTOP EXE)
# ============================================================

def firefox_exe_path() -> Path:
    candidates = [
        Path(r"C:\Program Files\Mozilla Firefox\firefox.exe"),
        Path(r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe"),
    ]
    for p in candidates:
        if p.exists():
            return p
    raise FileNotFoundError(
        "Desktop Firefox not found in Program Files. "
        "Install Firefox from mozilla.org (not the Microsoft Store)."
    )

def firefox_policies_path() -> Path:
    fx = firefox_exe_path()
    return fx.parent / "distribution" / "policies.json"

def ensure_dir(p: Path) -> None:
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        print_exc(f"ensure_dir({p})")
        if FAIL_FAST_ON_CRITICAL_ERRORS:
            raise

def backup_path(policies_path: Path) -> Path:
    return policies_path.with_name("policies.json.focus_backup")

def hosts_path() -> Path:
    return Path(r"C:\Windows\System32\drivers\etc\hosts")

def hosts_backup_path() -> Path:
    return app_dir() / "hosts.focus_backup"

def stop_signal_path() -> Path:
    return app_dir() / "focusmode.stop"

def heartbeat_path() -> Path:
    return app_dir() / "focusmode.heartbeat"


# ============================================================
# HOSTS (BACKUP + APPLY + RESET)
# ============================================================

def backup_hosts() -> None:
    try:
        hp = hosts_path()
        bp = hosts_backup_path()
        if not bp.exists():
            shutil.copy2(hp, bp)
            print_info(f" Backed up hosts -> {bp}")
    except Exception:
        print_exc("backup_hosts (non-fatal)")

def reset_hosts_to_default() -> None:
    try:
        hp = hosts_path()
        hp.write_text(HOSTS_DEFAULT_CONTENT, encoding="utf-8")
        print_info(" Hosts file reset to default")
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
        print_info(" Hosts blocking applied")
    except Exception:
        print_exc("apply_hosts_block")
        raise


# ============================================================
# FIREFOX PROFILE / SITE DATA CLEAR
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
# POLICIES BACKUP / RESTORE / WRITE
# ============================================================

def backup_existing(policies_path: Path) -> None:
    try:
        bkp = backup_path(policies_path)
        ensure_dir(policies_path)

        if policies_path.exists():
            shutil.copy2(policies_path, bkp)
            print_info(f" Backed up policies.json -> {bkp}")
        else:
            bkp.write_text(MARKER_NO_ORIGINAL, encoding="utf-8")
            print_info(f" No original policies.json; wrote marker backup -> {bkp}")
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

        print_info(f" Wrote Firefox policy: {policies_path}")
    except Exception:
        print_exc("write_policy")
        if FAIL_FAST_ON_CRITICAL_ERRORS:
            raise


# ============================================================
# FIREFOX PROCESS CONTROL
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

def launch_firefox() -> None:
    fx = firefox_exe_path()
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
    global _POLICIES_PATH, _CLEANED
    if _CLEANED:
        return
    _CLEANED = True

    # Close Firefox and clear site data
    _close_and_clear_site_data_best_effort()
    wait_for_firefox_exit()
    # Restore policies.json
    if _POLICIES_PATH is not None:
        try:
            restored = restore_from_backup(_POLICIES_PATH)
            if restored:
                print_info("Restored Firefox policies.json to original state.")
            else:
                print_info("No backup found to restore (nothing to do).")
        except Exception:
            print_exc("cleanup.restore_from_backup (non-fatal)")

    # Reset hosts
    if RESET_HOSTS_ON_EXIT:
        try:
            reset_hosts_to_default()
            print_info("Reset hosts file to Windows default (cleared all custom blocks/entries).")
        except Exception:
            print_exc("cleanup.reset_hosts_to_default (non-fatal)")

    # Restart Firefox unblocked
    if AUTO_RESTART_FIREFOX:
        try:
            print_info("Restarting Firefox so the unblocked state takes effect...")
            launch_firefox()
            verify_firefox_binary(firefox_exe_path())
        except Exception:
            print_exc("cleanup.launch_firefox (non-fatal)")

def safe_recover_if_needed() -> None:
    """
    If a previous run crashed/killed and left a backup marker behind, restore it.
    This is best-effort and safe to run at startup.
    """
    try:
        pp = firefox_policies_path()
        if restore_from_backup(pp):
            print_info("Startup recovery: restored original Firefox policies from backup.")
    except Exception:
        print_exc("safe_recover_if_needed (non-fatal)")

    # If you want: optionally reset hosts at startup when you suspect prior hard-kill.
    # This is potentially destructive to custom entries, so we only do it if enabled.
    if RESET_HOSTS_ON_START:
        try:
            reset_hosts_to_default()
            print_info("Startup recovery: reset hosts to default (enabled).")
        except Exception:
            print_exc("safe_recover_hosts (non-fatal)")


# ============================================================
# WORKER PROCESS (does blocking + watchdog)
# ============================================================

def _pid_alive(pid: int) -> bool:
    try:
        if pid <= 0:
            return False
        return psutil.pid_exists(pid)
    except Exception:
        return False

def worker_main(parent_pid: int | None) -> int:
    """
    Runs focus mode and watches for:
      - stop signal file
      - parent PID dying (Task Manager kill of UI)
    On either event, runs cleanup and exits.
    """
    global _POLICIES_PATH, _CLEANED
    _CLEANED = False

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

        fx = firefox_exe_path()
        policies_path = firefox_policies_path()
        _POLICIES_PATH = policies_path

        # If prior run crashed, recover first
        if restore_from_backup(policies_path):
            print_info("Recovered from previous interrupted run (restored original policies).")

        backup_hosts()
        apply_hosts_block()

        if RESET_HOSTS_ON_START:
            reset_hosts_to_default()
            print_info("Reset hosts file to default at startup (enabled).")

        # Ensure Firefox is closed before enabling policy
        _close_and_clear_site_data_best_effort()

        backup_existing(policies_path)
        write_policy(policies_path)

        # Ensure cleanup on normal exit signals (won't run on hard-kill)
        atexit.register(cleanup_and_optionally_restart)

        print_info(f"Using Firefox EXE: {fx}")
        print_info(f"Using Firefox policy file: {policies_path}")
        print_info("FOCUS MODE ON (worker active)")
        print_info("Worker will stop if UI requests stop, or if UI process is killed.")

        if AUTO_RESTART_FIREFOX:
            launch_firefox()
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
        print("\n🔥 WORKER FATAL ERROR — ABORTING 🔥")
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
        self.title("Study Mode – Focus Blocker")
        self.geometry("650x450")
        self.minsize(650, 450)

        self.log_q = queue.Queue()
        self._worker_proc: subprocess.Popen | None = None
        self._start_time: float | None = None

        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self._build_ui()
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

        # Stop phrase box
        phrase_frame = ttk.Frame(self)
        phrase_frame.pack(fill="x", **pad)

        ttk.Label(phrase_frame, text=f"To stop, type exactly: {STOP_PHRASE}").pack(anchor="w")
        self.phrase_entry = ttk.Entry(phrase_frame)
        self.phrase_entry.pack(fill="x")

        log_frame = ttk.LabelFrame(self, text="Activity Log")
        log_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.log_text = tk.Text(log_frame, height=12, wrap="word")
        self.log_text.pack(fill="both", expand=True, padx=8, pady=8)
        self.log_text.configure(state="disabled")

        ttk.Label(self, text="Tip: Run this as Administrator for hosts/policies to work.", foreground="gray").pack(
            anchor="w", padx=12, pady=(0, 10)
        )

    def _append_log(self, msg: str):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", msg.rstrip() + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _worker_running(self) -> bool:
        return self._worker_proc is not None and self._worker_proc.poll() is None

    def _refresh_status(self):
        running = self._worker_running()
        self.status_var.set("Status: ON (Focus Mode Active)" if running else "Status: OFF")
        self.start_btn.configure(state=("disabled" if running else "normal"))
        self.stop_btn.configure(state=("normal" if running else "disabled"))

        if running and self._start_time is not None:
            elapsed = int(time.time() - self._start_time)
            self.timer_var.set(f"Running: {elapsed//60:02d}:{elapsed%60:02d}")
        else:
            self.timer_var.set("")

        self.after(500, self._refresh_status)

    def _poll_worker_output(self):
        # Drain queued output from worker thread
        try:
            while True:
                msg = self.log_q.get_nowait()
                self._append_log(msg)
        except queue.Empty:
            pass

        self.after(200, self._poll_worker_output)

    def start_focus(self):
        if self._worker_running():
            return

        # Best-effort: clear stop signal
        try:
            sp = stop_signal_path()
            if sp.exists():
                sp.unlink()
        except Exception:
            pass

        self._append_log("Starting focus mode worker...")

        # Launch worker subprocess
        # We pass the UI's PID so worker can detect Task Manager kill of the UI.
        args = [sys.executable if not getattr(sys, "frozen", False) else sys.executable, str(Path(__file__).resolve()), "--worker", "--parent-pid", str(os.getpid())]

        # If frozen .exe, __file__ may not exist; in that case use sys.executable and args accordingly.
        if getattr(sys, "frozen", False):
            args = [sys.executable, "--worker", "--parent-pid", str(os.getpid())]

        try:
            self._worker_proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            self._start_time = time.time()
            threading.Thread(target=self._read_worker_stdout, daemon=True).start()
        except Exception as e:
            self._append_log(f"Failed to start worker: {e}")
            self._worker_proc = None
            self._start_time = None

    def _read_worker_stdout(self):
        try:
            if not self._worker_proc or not self._worker_proc.stdout:
                return
            for line in self._worker_proc.stdout:
                self.log_q.put(line.rstrip())
        except Exception as e:
            self.log_q.put(f"(UI) Worker output read error: {e}")

    def _stop_phrase_ok(self) -> bool:
        typed = self.phrase_entry.get().strip()
        return typed == STOP_PHRASE

    def stop_focus(self):
        if not self._worker_running():
            return

        if REQUIRE_STOP_PHRASE and not self._stop_phrase_ok():
            messagebox.showwarning("Stop blocked", f"Type the full stop phrase exactly:\n\n{STOP_PHRASE}")
            return

        if not messagebox.askyesno("Stop Focus Mode", "Turn OFF Focus Mode and restore normal browsing?"):
            return

        # Signal the worker to stop
        try:
            stop_signal_path().write_text("stop", encoding="utf-8")
        except Exception as e:
            self._append_log(f"Failed to write stop signal: {e}")

        # UI is not responsible for cleanup — worker is.
        self._append_log("Stop requested. Waiting for worker to exit...")
        self.phrase_entry.delete(0, "end")

    def on_close(self):
        """
        Closing UI should stop Focus Mode and undo blocks.
        """
        if self._worker_running():
            # Optional: keep your warning, but now we actually stop on close
            if not messagebox.askyesno(
                "Stop Focus Mode?",
                "Focus Mode is ON.\n\nClosing will STOP focus mode and restore browsing.\n\nStop and close?"
            ):
                return

            # Request worker stop (worker will run cleanup)
            try:
                stop_signal_path().write_text("stop", encoding="utf-8")
            except Exception as e:
                self._append_log(f"Failed to write stop signal: {e}")

            self._append_log("Close requested. Waiting for worker cleanup...")

            # Wait for worker to exit (so policies/hosts are restored)
            deadline = time.time() + 20  # seconds
            while self._worker_running() and time.time() < deadline:
                self.update()
                time.sleep(0.2)

            if self._worker_running():
                self._append_log("Worker still running; closing UI anyway (worker should still cleanup shortly).")

        self.destroy()

def wait_for_firefox_exit(timeout=10):
        end = time.time() + timeout
        while time.time() < end:
            if not is_firefox_running():
                return True
            time.sleep(0.2)
        return False
# ============================================================
# ENTRYPOINT + ARG PARSING
# ============================================================

def parse_args(argv: list[str]) -> dict:
    out = {"mode": "ui", "parent_pid": None}
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
    return out

def restore_only() -> int:
    """
    Manual restore mode:
      python script.py --restore
    Useful if you ever hard-kill BOTH processes and need cleanup.
    """
    try:
        pp = firefox_policies_path()
        global _POLICIES_PATH, _CLEANED
        _POLICIES_PATH = pp
        _CLEANED = False
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
        sys.exit(worker_main(parent_pid))

    # UI mode
    try:
        app = FocusUI()
        app.mainloop()
    except Exception:
        print("\n UI FATAL ERROR — PROGRAM ABORTED ")
        traceback.print_exc()
        log("UI FATAL:\n" + traceback.format_exc())
        if getattr(sys, "frozen", False):
            input("\nPress ENTER to exit...")
        sys.exit(1)


if __name__ == "__main__":
    main()
