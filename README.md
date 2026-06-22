# mac-security-scan

A standalone bash script that runs a local security audit on your Mac and generates a self-deleting HTML report.

No dependencies on external services, no tokens, no cloud — everything runs locally.

## What it checks

| # | Check | Severity if failed |
|---|---|---|
| 1 | System Integrity Protection (SIP) | Critical |
| 2 | FileVault disk encryption | High |
| 3 | Application Firewall | Critical |
| 4 | Gatekeeper | High |
| 5 | Ports listening on all network interfaces | Medium |
| 6 | Non-Apple LaunchAgents / LaunchDaemons | Low |
| 7 | SSH authorized_keys & permissions | High / Medium |
| 8 | Suspicious /etc/hosts entries | Medium |
| 9 | Hardcoded secrets in shell profiles | High |
| 10 | Outdated security-relevant Homebrew packages | Medium |
| 11 | Python package CVEs (via pip-audit) | High |
| 12 | Crontab entries | Medium |

## Requirements

- macOS (tested on macOS 13+)
- Bash 3.2+ (pre-installed on macOS)
- Optional: `pip-audit` for Python CVE scanning

```bash
pip install pip-audit
```

- Optional: `brew` for Homebrew package checks

## Usage

```bash
chmod +x mac-security-scan.sh
./mac-security-scan.sh
```

The report opens automatically in your default browser and is **deleted from disk after 10 seconds** — it is never saved permanently.

## Report

The HTML report groups findings by severity:

- **Critical** — fix immediately
- **High** — fix soon
- **Medium** — review and address
- **Low / Info** — informational
- **Passed** — checks that are clean

## Security design of the script itself

- `umask 077` — report file is owner-readable only
- `mktemp` — unpredictable temp filename, resistant to symlink attacks
- `chmod 600` — report file locked to owner on creation
- All system output is HTML-escaped before insertion into the report
- `Content-Security-Policy` header blocks scripts in the HTML report
- PATH is restricted to known safe directories
- No external network calls
- No data is sent anywhere

## License

MIT
