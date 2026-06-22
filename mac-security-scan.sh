#!/usr/bin/env bash
# mac-security-scan.sh — macXscan v2
# Usage: ./mac-security-scan.sh  (or double-click macXscan.command)

set -euo pipefail
umask 077

# Add all Python framework bin dirs so pip-audit is findable regardless of version
for _pybin in /Library/Frameworks/Python.framework/Versions/*/bin; do
  PATH="$PATH:$_pybin"
done
unset _pybin
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"

REPORT_DATE=$(date '+%Y-%m-%d %H:%M:%S')
REPORT_FILE=$(mktemp /tmp/mac-security-XXXXXX.html)
chmod 600 "$REPORT_FILE"

MACHINE_NAME=$(scutil --get ComputerName 2>/dev/null || hostname)
MACOS_VER=$(sw_vers -productVersion 2>/dev/null || echo "unknown")

# ── Counters & per-severity buckets ───────────────────────────────────────────
CRITICAL=0; HIGH=0; MEDIUM=0; LOW=0; PASSED=0
F_CRITICAL=""; F_HIGH=""; F_MEDIUM=""; F_LOW=""; F_OK=""

html_escape() {
  local s="$1"
  s="${s//&/&amp;}"
  s="${s//</&lt;}"
  s="${s//>/&gt;}"
  s="${s//\"/&quot;}"
  s="${s//\'/&#39;}"
  printf '%s' "$s"
}

# add_finding severity title desc [fix_cmd] [settings_url]
add_finding() {
  local severity="$1"
  local title;       title=$(html_escape "$2")
  local desc;        desc=$(html_escape "$3")
  local fix="${4:-}"
  local settings_url="${5:-}"

  local fix_html="" settings_html=""
  [[ -n "$fix" ]] && fix_html="<div class=\"fix\">$(html_escape "$fix")</div>"
  # settings_url is always a hardcoded x-apple.systempreferences: link — never from system data
  [[ -n "$settings_url" ]] && settings_html="<a class=\"settings-btn\" href=\"$(html_escape "$settings_url")\">Open Settings →</a>"

  # Re-allow <br> built internally for list entries
  desc="${desc//&lt;br&gt;/<br>}"

  case "$severity" in
    critical) (( CRITICAL++ )) ;;
    high)     (( HIGH++ ))     ;;
    medium)   (( MEDIUM++ ))   ;;
    low)      (( LOW++ ))      ;;
    ok)       (( PASSED++ ))   ;;
  esac

  local badge; badge=$(printf '%s' "$severity" | tr '[:lower:]' '[:upper:]')
  local block="<div class=\"item\">
    <span class=\"badge ${severity}\">${badge}</span>
    <div class=\"item-content\">
      <div class=\"title\">${title}</div>
      <div class=\"desc\">${desc}</div>
      <div class=\"actions\">${fix_html}${settings_html}</div>
    </div>
  </div>"

  case "$severity" in
    critical) F_CRITICAL+="$block" ;;
    high)     F_HIGH+="$block"     ;;
    medium)   F_MEDIUM+="$block"   ;;
    low)      F_LOW+="$block"      ;;
    ok)       F_OK+="$block"       ;;
  esac
}

build_section() {
  local heading="$1" content="$2"
  [[ -z "$content" ]] && return
  printf '<section><h2>%s</h2>%s</section>' "$heading" "$content"
}

echo "Starting macXscan on ${MACHINE_NAME}..."

# ── 1. System Integrity Protection ────────────────────────────────────────────
echo "[1/10] System Integrity Protection..."

SIP=$(csrutil status 2>/dev/null || true)
if printf '%s' "$SIP" | grep -q "enabled"; then
  add_finding "ok" "System Integrity Protection — On" \
    "A core macOS safety net is active. It prevents any program from modifying critical system files."
else
  add_finding "critical" "System Integrity Protection — Off" \
    "A core macOS safety net is turned off. This lets any program modify critical system files, making your Mac much easier to compromise." \
    "Boot into Recovery Mode (hold Power on startup) → run: csrutil enable"
fi

# ── 2. FileVault ──────────────────────────────────────────────────────────────
echo "[2/10] FileVault..."

FV=$(fdesetup status 2>/dev/null || true)
if printf '%s' "$FV" | grep -q "On"; then
  add_finding "ok" "FileVault disk encryption — On" \
    "Your Mac's storage is fully encrypted. If someone gets your Mac they cannot read your files without your password."
else
  add_finding "high" "FileVault — Off" \
    "Your Mac's data is not encrypted. If someone physically gets your Mac, they can read all your files without knowing your password." \
    "" \
    "x-apple.systempreferences:com.apple.preference.security?FDE"
fi

# ── 3. Firewall ───────────────────────────────────────────────────────────────
echo "[3/10] Firewall..."

FW=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || true)
if printf '%s' "$FW" | grep -q "enabled"; then
  add_finding "ok" "Firewall — On" \
    "Your Mac is blocking unwanted incoming connections from other devices on the network."
else
  add_finding "critical" "Firewall — Off" \
    "Your Mac is not blocking unwanted incoming connections. Other devices on the same Wi-Fi can attempt to connect to services running on your Mac." \
    "" \
    "x-apple.systempreferences:com.apple.preference.security?Firewall"
fi

# ── 4. Gatekeeper ─────────────────────────────────────────────────────────────
echo "[4/10] Gatekeeper..."

GK=$(spctl --status 2>/dev/null || true)
if printf '%s' "$GK" | grep -q "enabled"; then
  add_finding "ok" "Gatekeeper — On" \
    "Your Mac checks that apps are from trusted developers before opening them."
else
  add_finding "high" "Gatekeeper — Off" \
    "Your Mac will open apps from any source without any safety check, including apps that could be harmful." \
    "sudo spctl --master-enable" \
    "x-apple.systempreferences:com.apple.preference.security?General"
fi

# ── 5. macOS Software Updates ─────────────────────────────────────────────────
echo "[5/10] Software updates (this may take a moment)..."

SW_OUT=$(softwareupdate -l 2>/dev/null || true)
SEC_UPDATES=$(printf '%s' "$SW_OUT" | grep -i "recommended\|security\|\*" | grep -v "^Software\|^No new" || true)

if [[ -n "$SEC_UPDATES" ]]; then
  UPDATE_LIST=""
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    UPDATE_LIST+="• $(html_escape "$line")<br>"
  done <<< "$SEC_UPDATES"
  add_finding "high" "macOS security updates are available" \
    "Your Mac has security patches waiting to be installed. Keeping macOS up to date is one of the most effective ways to stay protected.<br>${UPDATE_LIST}" \
    "" \
    "x-apple.systempreferences:com.apple.preferences.softwareupdate"
else
  add_finding "ok" "macOS is up to date" \
    "No pending security updates found."
fi

# ── 6. Open Ports ─────────────────────────────────────────────────────────────
echo "[6/10] Open ports..."

LISTENING=$(lsof -iTCP -sTCP:LISTEN -nP 2>/dev/null | grep -v "^COMMAND" || true)
PUBLIC_PORTS=$(printf '%s' "$LISTENING" | grep "\*:" | awk '{print $9, $1}' | sort -u || true)

if [[ -n "$PUBLIC_PORTS" ]]; then
  PORT_LIST=""
  while IFS= read -r line; do
    PORT_LIST+="• $(html_escape "$line")<br>"
  done <<< "$PUBLIC_PORTS"
  add_finding "medium" "Background services are accepting network connections" \
    "These services on your Mac are reachable from other devices on the same Wi-Fi network. This is low risk if your firewall is on, but worth knowing about.<br>${PORT_LIST}" \
    "Turn off unused services: System Settings → General → AirDrop &amp; Handoff"
else
  add_finding "ok" "No services exposed to the local network" \
    "All background services are only accessible from your Mac itself."
fi

# ── 7. LaunchAgents / LaunchDaemons ───────────────────────────────────────────
echo "[7/10] Auto-start programs..."

NON_APPLE_AGENTS=""
for dir in "$HOME/Library/LaunchAgents" "/Library/LaunchAgents" "/Library/LaunchDaemons"; do
  if [[ -d "$dir" ]]; then
    while IFS= read -r -d '' plist; do
      name=$(basename "$plist")
      if [[ "$name" != com.apple.* && "$name" != io.macxscan.* ]]; then
        NON_APPLE_AGENTS+="$name"$'\n'
      fi
    done < <(find "$dir" -maxdepth 1 -name "*.plist" -print0 2>/dev/null)
  fi
done

if [[ -n "$NON_APPLE_AGENTS" ]]; then
  AGENT_LIST=""
  while IFS= read -r agent; do
    [[ -z "$agent" ]] && continue
    AGENT_LIST+="• $(html_escape "$agent")<br>"
  done <<< "$NON_APPLE_AGENTS"
  add_finding "low" "Third-party programs start automatically at login" \
    "These non-Apple programs launch automatically when you log in. Make sure you recognise all of them.<br>${AGENT_LIST}" \
    "Review login items in System Settings → General → Login Items" \
    "x-apple.systempreferences:com.apple.LoginItems-Settings.extension"
else
  add_finding "ok" "No unexpected auto-start programs" \
    "Only Apple system services start automatically at login."
fi

# ── 8. SSH ────────────────────────────────────────────────────────────────────
echo "[8/10] SSH access..."

if [[ -f "$HOME/.ssh/authorized_keys" ]] && [[ -s "$HOME/.ssh/authorized_keys" ]]; then
  KEY_COUNT=$(wc -l < "$HOME/.ssh/authorized_keys" | tr -d ' ')
  add_finding "high" "Your Mac allows remote login via saved keys (${KEY_COUNT} key(s))" \
    "Someone with the matching private key can log into your Mac remotely over SSH without a password. Make sure these keys are yours and still needed." \
    "Review the keys: cat ~/.ssh/authorized_keys — remove any you don't recognise"
else
  add_finding "ok" "No remote SSH access configured" \
    "Your Mac cannot be logged into remotely via SSH key authentication."
fi

if [[ -d "$HOME/.ssh" ]]; then
  SSH_PERMS=$(stat -f "%Lp" "$HOME/.ssh" 2>/dev/null || echo "000")
  if [[ "$SSH_PERMS" != "700" ]]; then
    add_finding "medium" "SSH folder permissions are too open (${SSH_PERMS})" \
      "Your SSH folder should only be readable by you. Other users on this Mac may be able to see your SSH keys." \
      "chmod 700 ~/.ssh"
  else
    add_finding "ok" "SSH folder is locked down correctly" \
      "Your SSH folder is only accessible by your user account."
  fi
fi

# ── 9. /etc/hosts ─────────────────────────────────────────────────────────────
echo "[9/10] Network settings..."

SUSPICIOUS_HOSTS=$(grep -Ev "^#|^[[:space:]]*$|localhost|broadcasthost|ip6|\.local$" /etc/hosts 2>/dev/null || true)
if [[ -n "$SUSPICIOUS_HOSTS" ]]; then
  HOST_LIST=""
  while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    HOST_LIST+="• $(html_escape "$entry")<br>"
  done <<< "$SUSPICIOUS_HOSTS"
  add_finding "medium" "Unusual network redirect entries found" \
    "Your Mac has custom entries that redirect certain website addresses. This is sometimes done legitimately by developers, but can also be a sign of tampering.<br>${HOST_LIST}" \
    "Review the file: open /etc/hosts in a text editor and remove anything unexpected"
else
  add_finding "ok" "Network address settings look clean" \
    "No unexpected website redirects found."
fi

# ── 10. Shell Secrets ─────────────────────────────────────────────────────────
echo "[10/10] Checking for exposed secrets..."

SECRET_HITS=0
for f in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.zprofile" "$HOME/.profile"; do
  if [[ -f "$f" ]]; then
    count=$(grep -iE "(api.?key|secret|token|password)\s*=" "$f" 2>/dev/null | grep -cv "^#" || true)
    (( SECRET_HITS += count )) || true
  fi
done

if [[ "$SECRET_HITS" -gt 0 ]]; then
  add_finding "high" "${SECRET_HITS} possible password or API key(s) found in shell config" \
    "It looks like API keys, tokens, or passwords may be stored as plain text in your terminal startup files. Anyone who can read those files can steal those credentials." \
    "Move secrets to Keychain: security add-generic-password -a \$USER -s NAME -w YOUR_VALUE"
else
  add_finding "ok" "No passwords or API keys found in shell config" \
    "No plain-text credentials detected in your terminal startup files."
fi

# ── Homebrew ──────────────────────────────────────────────────────────────────
if command -v brew &>/dev/null; then
  OUTDATED=$(brew outdated 2>/dev/null || true)
  SEC_OUTDATED=$(printf '%s' "$OUTDATED" | grep -iE "openssl|curl|libssl|python|node|git|wget|libxml|sqlite|cryptography|certifi|ca-certificates|libressl|openssh|gnupg|gpg" || true)
  ALL_COUNT=$(printf '%s\n' "$OUTDATED" | grep -c "." || true)
  SEC_COUNT=$(printf '%s\n' "$SEC_OUTDATED" | grep -c "." || true)

  if [[ "$SEC_COUNT" -gt 0 ]]; then
    PKG_LIST=""
    while IFS= read -r pkg; do
      [[ -z "$pkg" ]] && continue
      PKG_LIST+="• $(html_escape "$pkg")<br>"
    done <<< "$SEC_OUTDATED"
    UPGRADE_CMD="brew upgrade $(printf '%s\n' "$SEC_OUTDATED" | awk '{print $1}' | tr '\n' ' ')"
    add_finding "medium" "${SEC_COUNT} developer tool(s) have security updates" \
      "These installed tools have newer versions available that include security fixes:<br>${PKG_LIST}" \
      "$UPGRADE_CMD"
  else
    add_finding "ok" "Developer tools are up to date" \
      "All security-relevant Homebrew packages are current."
  fi

  if [[ "$ALL_COUNT" -gt 0 ]]; then
    add_finding "low" "${ALL_COUNT} Homebrew package(s) have updates available" \
      "Non-critical updates are available. Run brew upgrade to update everything." \
      "brew upgrade"
  fi
fi

# ── pip audit ─────────────────────────────────────────────────────────────────
if command -v pip-audit &>/dev/null; then
  PIP_AUDIT_OUT=$(pip-audit --format=columns 2>/dev/null | grep -Ev "^Name|^---|^No known" || true)
  VULN_COUNT=$(printf '%s\n' "$PIP_AUDIT_OUT" | grep -c "." || true)

  if [[ "$VULN_COUNT" -gt 0 ]]; then
    VULN_LIST=""
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      VULN_LIST+="• $(html_escape "$line")<br>"
    done <<< "$PIP_AUDIT_OUT"
    PKGS=$(printf '%s\n' "$PIP_AUDIT_OUT" | awk '{print $1}' | sort -u | tr '\n' ' ')
    add_finding "high" "${VULN_COUNT} Python package(s) have known security vulnerabilities" \
      "These Python packages installed on your Mac have publicly known security flaws:<br>${VULN_LIST}" \
      "pip install --upgrade ${PKGS}"
  else
    add_finding "ok" "Python packages have no known vulnerabilities" \
      "pip-audit found no security issues in your installed Python packages."
  fi
else
  add_finding "low" "Python security scanner not installed" \
    "Install pip-audit to enable Python package vulnerability scanning." \
    "pip install pip-audit"
fi

# ── Crontab ───────────────────────────────────────────────────────────────────
CRON=$(crontab -l 2>/dev/null | grep -Ev "^#|^[[:space:]]*$" || true)
if [[ -n "$CRON" ]]; then
  CRON_LIST=""
  while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    CRON_LIST+="• $(html_escape "$entry")<br>"
  done <<< "$CRON"
  add_finding "medium" "Scheduled tasks found in crontab" \
    "These tasks are set to run automatically on a schedule. Review them to make sure they are expected and safe:<br>${CRON_LIST}" \
    "crontab -e  to review or remove entries"
else
  add_finding "ok" "No scheduled cron tasks" \
    "No automatically scheduled tasks found."
fi

# ── Build HTML ─────────────────────────────────────────────────────────────────
echo "Generating report..."

TOTAL_ISSUES=$(( CRITICAL + HIGH + MEDIUM + LOW ))

CRITICAL_SEC=$(build_section "Critical"  "$F_CRITICAL")
HIGH_SEC=$(build_section "High"          "$F_HIGH")
MEDIUM_SEC=$(build_section "Medium"      "$F_MEDIUM")
LOW_SEC=$(build_section "Low / Info"     "$F_LOW")
OK_SEC=$(build_section "Passed"          "$F_OK")

cat > "$REPORT_FILE" <<HTMLEOF
<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
<title>macXscan Report</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #0f1117; color: #e2e8f0; line-height: 1.6; padding: 2rem 1rem; }
  .container { max-width: 860px; margin: 0 auto; }
  .header { margin-bottom: 2rem; }
  .header h1 { font-size: 1.6rem; font-weight: 700; }
  .header h1 span { color: #3b82f6; }
  .subtitle { color: #64748b; font-size: 0.875rem; margin-top: 0.25rem; }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 2.5rem; }
  .stat-card { background: #1e2130; border-radius: 10px; padding: 1.1rem 1.25rem; border-left: 4px solid; }
  .stat-card.red    { border-color: #ef4444; }
  .stat-card.orange { border-color: #f97316; }
  .stat-card.yellow { border-color: #eab308; }
  .stat-card.blue   { border-color: #3b82f6; }
  .stat-card.green  { border-color: #22c55e; }
  .stat-card .label { font-size: 0.7rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.06em; }
  .stat-card .value { font-size: 2rem; font-weight: 700; margin-top: 0.1rem; }
  .stat-card.red .value    { color: #f87171; }
  .stat-card.orange .value { color: #fb923c; }
  .stat-card.yellow .value { color: #facc15; }
  .stat-card.blue .value   { color: #60a5fa; }
  .stat-card.green .value  { color: #4ade80; }
  section { margin-bottom: 2rem; }
  h2 { font-size: 0.75rem; font-weight: 700; color: #475569; text-transform: uppercase; letter-spacing: 0.12em; margin-bottom: 0.75rem; border-bottom: 1px solid #1e2130; padding-bottom: 0.4rem; }
  .item { background: #1e2130; border-radius: 8px; padding: 1rem 1.1rem; margin-bottom: 0.5rem; display: flex; align-items: flex-start; gap: 0.75rem; }
  .badge { flex-shrink: 0; font-size: 0.65rem; font-weight: 700; padding: 0.2rem 0.45rem; border-radius: 4px; text-transform: uppercase; letter-spacing: 0.06em; margin-top: 0.2rem; }
  .badge.critical { background: #7f1d1d; color: #fca5a5; }
  .badge.high     { background: #7c2d12; color: #fdba74; }
  .badge.medium   { background: #713f12; color: #fde68a; }
  .badge.low      { background: #1e3a5f; color: #93c5fd; }
  .badge.ok       { background: #14532d; color: #86efac; }
  .item-content { flex: 1; min-width: 0; }
  .item-content .title { font-weight: 600; font-size: 0.95rem; }
  .item-content .desc  { color: #94a3b8; font-size: 0.85rem; margin-top: 0.25rem; }
  .actions { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.5rem; align-items: center; }
  .fix { color: #4ade80; font-size: 0.78rem; font-family: "SF Mono", monospace; background: #0d1117; padding: 0.3rem 0.6rem; border-radius: 4px; word-break: break-all; }
  .settings-btn { display: inline-block; font-size: 0.78rem; font-weight: 600; color: #60a5fa; background: #1e3a5f; padding: 0.3rem 0.7rem; border-radius: 4px; text-decoration: none; }
  .settings-btn:hover { background: #2563eb; color: #fff; }
  footer { margin-top: 3rem; color: #334155; font-size: 0.78rem; text-align: center; border-top: 1px solid #1e2130; padding-top: 1.5rem; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>mac<span>X</span>scan</h1>
    <p class="subtitle">Host: <strong>$(html_escape "$MACHINE_NAME")</strong> &nbsp;·&nbsp; ${REPORT_DATE} &nbsp;·&nbsp; macOS ${MACOS_VER}</p>
  </div>

  <div class="summary-grid">
    <div class="stat-card red">   <div class="label">Critical</div><div class="value">${CRITICAL}</div></div>
    <div class="stat-card orange"><div class="label">High</div>    <div class="value">${HIGH}</div></div>
    <div class="stat-card yellow"><div class="label">Medium</div>  <div class="value">${MEDIUM}</div></div>
    <div class="stat-card blue">  <div class="label">Low</div>     <div class="value">${LOW}</div></div>
    <div class="stat-card green"> <div class="label">Passed</div>  <div class="value">${PASSED}</div></div>
  </div>

  ${CRITICAL_SEC}
  ${HIGH_SEC}
  ${MEDIUM_SEC}
  ${LOW_SEC}
  ${OK_SEC}

  <footer>macXscan &nbsp;·&nbsp; ${REPORT_DATE} &nbsp;·&nbsp; This report is deleted from disk automatically after viewing.</footer>
</div>
</body>
</html>
HTMLEOF

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Scan complete."
echo "  Critical : $CRITICAL"
echo "  High     : $HIGH"
echo "  Medium   : $MEDIUM"
echo "  Low      : $LOW"
echo "  Passed   : $PASSED"
echo "  Total    : $TOTAL_ISSUES issues"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

open "$REPORT_FILE" 2>/dev/null
( sleep 10 && rm -f "$REPORT_FILE" ) &
