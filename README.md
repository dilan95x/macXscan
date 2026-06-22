# macXscan

A one-click Mac security scanner. Checks your system for common security issues and opens a clean HTML report in your browser — no accounts, no cloud, no data ever leaves your Mac.

## Quick start

**Option A — Double-click (easiest)**
Download the repo, then double-click `macXscan.command` in Finder.

**Option B — Run the installer**
```bash
bash install.sh
```
The installer sets up permissions, optionally installs the Python CVE scanner, and optionally sets up a weekly auto-scan.

**Option C — Terminal**
```bash
chmod +x mac-security-scan.sh
./mac-security-scan.sh
```

## What it checks

| Check | Severity if failed |
|---|---|
| System Integrity Protection (SIP) | Critical |
| FileVault disk encryption | High |
| Application Firewall | Critical |
| Gatekeeper (app safety checks) | High |
| macOS security updates | High |
| Services exposed to local network | Medium |
| Non-Apple auto-start programs | Low |
| SSH remote access configuration | High / Medium |
| Unusual network redirects (/etc/hosts) | Medium |
| Passwords / API keys in shell config | High |
| Outdated security-relevant Homebrew packages | Medium |
| Python package CVEs (via pip-audit) | High |
| Scheduled cron tasks | Medium |

## The report

- Opens automatically in your browser
- **Deleted from disk after 10 seconds** — never stored permanently
- Each finding has a plain-English description and an **Open Settings →** button that takes you directly to the relevant macOS settings pane
- Colour-coded by severity: Critical → High → Medium → Low → Passed

## Weekly auto-scan

Run `bash install.sh` and choose yes when asked. macXscan will scan every Monday at 9am and open the report in your browser automatically.

To remove the weekly scan:
```bash
launchctl unload ~/Library/LaunchAgents/io.macxscan.weekly.plist
rm ~/Library/LaunchAgents/io.macxscan.weekly.plist
```

## Optional dependency

`pip-audit` enables Python package CVE scanning. The installer will offer to install it, or you can do it manually:
```bash
pip install pip-audit
```

## Security design

- `umask 077` — report file is owner-readable only
- `mktemp` — unpredictable temp filename, prevents symlink attacks
- `chmod 600` — report file locked to owner on creation
- All system output is HTML-escaped before going into the report
- `Content-Security-Policy` header in the report blocks any injected scripts
- PATH is restricted to known-safe system directories
- The macOS update check (`softwareupdate -l`) contacts Apple's update servers to fetch available update metadata — no scan results or personal data are sent
- All other checks run entirely locally with no network calls
- No scan data is sent anywhere

## Requirements

- macOS 13 (Ventura) or later
- Bash 3.2+ (pre-installed on all Macs)

## License

MIT — Copyright (c) 2026 Dilan
