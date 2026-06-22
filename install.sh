#!/usr/bin/env bash
# install.sh — macXscan installer
# Sets up permissions, optional dependencies, and optional weekly auto-scan.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCAN_SCRIPT="$SCRIPT_DIR/mac-security-scan.sh"
AGENT_LABEL="io.macxscan.weekly"
AGENT_PLIST="$HOME/Library/LaunchAgents/${AGENT_LABEL}.plist"

echo ""
echo "  macXscan installer"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── Step 1: Permissions ───────────────────────────────────────────────────────
chmod +x "$SCAN_SCRIPT"
[[ -f "$SCRIPT_DIR/macXscan.command" ]] && chmod +x "$SCRIPT_DIR/macXscan.command"
echo "✓ Script permissions set"

# ── Step 2: pip-audit ─────────────────────────────────────────────────────────
if ! command -v pip-audit &>/dev/null; then
  echo ""
  echo "pip-audit is not installed. It enables Python package CVE scanning."
  printf "  Install pip-audit now? [y/N] "
  read -r answer
  if [[ "$answer" =~ ^[Yy]$ ]]; then
    pip3 install pip-audit -q && echo "✓ pip-audit installed"
  else
    echo "  Skipped — Python CVE scanning will be unavailable until installed."
  fi
else
  echo "✓ pip-audit already installed"
fi

# ── Step 3: Weekly auto-scan ──────────────────────────────────────────────────
echo ""
if [[ -f "$AGENT_PLIST" ]]; then
  echo "✓ Weekly auto-scan already configured"
else
  echo "macXscan can run automatically every Monday at 9am and show a notification if issues are found."
  printf "  Set up weekly auto-scan? [y/N] "
  read -r answer
  if [[ "$answer" =~ ^[Yy]$ ]]; then
    mkdir -p "$HOME/Library/LaunchAgents"
    cat > "$AGENT_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${AGENT_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>${SCAN_SCRIPT}</string>
  </array>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Weekday</key>
    <integer>1</integer>
    <key>Hour</key>
    <integer>9</integer>
    <key>Minute</key>
    <integer>0</integer>
  </dict>
  <key>StandardOutPath</key>
  <string>${HOME}/Library/Logs/macxscan.log</string>
  <key>StandardErrorPath</key>
  <string>${HOME}/Library/Logs/macxscan.log</string>
</dict>
</plist>
PLIST
    chmod 600 "$AGENT_PLIST"
    launchctl load "$AGENT_PLIST" 2>/dev/null && echo "✓ Weekly auto-scan enabled (every Monday at 9am)"
  else
    echo "  Skipped — run mac-security-scan.sh manually whenever you like."
  fi
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Installation complete."
echo ""
echo "  Run a scan now:       bash mac-security-scan.sh"
echo "  Or double-click:      macXscan.command"
echo ""

printf "  Run a scan now? [y/N] "
read -r answer
[[ "$answer" =~ ^[Yy]$ ]] && bash "$SCAN_SCRIPT"
