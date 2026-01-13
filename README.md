# Focus Mode Blocker (Windows + Firefox)

A Windows tool that enables a "focus mode" by blocking distracting sites (YouTube, Discord, Instagram) using:

- Windows `hosts` file blocking
- Firefox Enterprise Policies (`policies.json`) WebsiteFilter
- Optional process-killing (e.g., Discord.exe)

Includes backup/restore logic so settings can be reverted when Focus Mode stops.

## Features
- Blocks a configured list of domains
- Optionally kills blocked desktop apps (e.g., Discord)
- Backs up and restores:
  - Firefox `distribution/policies.json`
  - Windows hosts file (and/or resets hosts to Windows default, depending on config)
- Attempts to restart Firefox so policy changes take effect
- UI mode: Start/Stop with a required stop phrase

## Requirements
- Windows 10/11
- Firefox (Desktop install from mozilla.org, not Microsoft Store)
- Python 3.10+ recommended
- Admin privileges (required to modify hosts + Program Files)

Python packages:
- `psutil`
- `pywin32` (optional but recommended for graceful window close)

Install:
```bash
pip install psutil pywin32
