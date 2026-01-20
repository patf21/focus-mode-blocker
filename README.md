# Study Mode – Focus Blocker (Windows)

A **Windows-only focus tool** that enables a system-wide *Focus Mode* by temporarily blocking distracting websites (YouTube, Discord, Instagram, Reddit, LinkedIn) using the Windows **hosts file**.

This version is intentionally **AV-friendly**, avoids browser policy manipulation, and includes **crash-safe recovery** so you don’t get locked out if the app is closed unexpectedly.

---

## How It Works

When Focus Mode is started:

- Selected domains are blocked **system-wide** via the Windows `hosts` file  
  (affects all browsers and the Discord desktop app)
- The Discord desktop app is **optionally closed once** at startup (no kill loop)
- A short **audio ding** plays to confirm Focus Mode is ON

When Focus Mode stops (or if the app crashes):

- All Focus Mode blocks are **fully removed**
- DNS cache is flushed so access is restored immediately
- A different **audio ding** confirms Focus Mode is OFF

---

## Key Design Goals

- No browser enterprise policies
- No continuous process killing
- No auto-elevation tricks
- No persistent background services
- No permanent system changes

Everything is temporary, reversible, and cleaned up automatically.

---

## Features

### Core
- System-wide blocking via the Windows `hosts` file
- Blocks configurable domains:
  - YouTube
  - Discord
  - Instagram
  - Reddit
  - LinkedIn
- Optional one-time Discord app close on Focus Mode start
- Start / Stop UI with a required stop phrase
- Optional timer (auto-stop after N minutes)

### Safety & Recovery (Failsafes)
- **Crash-safe cleanup**
  - If the UI crashes or is killed, the worker detects it and restores access
- **Startup auto-recovery**
  - If a previous session didn’t exit cleanly, the app automatically unblocks everything on next launch
- **Aggressive unblock**
  - Removes:
    - Marked Focus Mode blocks
    - Any stray `127.0.0.1`, `0.0.0.0`, or `::1` entries for blocked domains
- DNS cache flush on stop/recovery
- Manual **Restore Now** button to force unblocking at any time

### User Feedback
- Audible **ding when Focus Mode starts**
- Audible **ding when Focus Mode stops**
- Live activity log in the UI
- Clear status indicator (ON / OFF)

---

## What This Version Does *Not* Do

- ❌ No Firefox Enterprise Policies (`policies.json`)
- ❌ No writing to `Program Files`
- ❌ No background service or startup persistence
- ❌ No continuous app-killing loops
- ❌ No silent auto-elevation

These were intentionally removed to reduce antivirus false positives and prevent system lock-outs.

---

## Requirements

- Windows 10 or Windows 11
- Python 3.10+ recommended
- **Administrator privileges** (required to modify the hosts file)

### Python Dependencies
```bash
pip install psutil
```
Running the App
UI Mode (normal use)
python study_mode_focus_blocker.py


Run as Administrator when starting Focus Mode.

Manual Restore (emergency unblock)

If something ever goes wrong, force cleanup with:

python study_mode_focus_blocker.py --restore


This:

Removes all Focus Mode blocks

Flushes DNS

Clears any stale session state


Security & Antivirus Notes

This project:

Modifies the Windows hosts file (requires admin)

Does not install persistence

Does not collect data

Does not communicate over the network

All behavior is temporary, transparent, and fully reversible.
