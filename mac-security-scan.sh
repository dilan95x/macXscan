#!/usr/bin/env bash
# mac-security-scan.sh — standalone security scan with HTML report
# Usage: ./mac-security-scan.sh

set -euo pipefail
umask 077

# Add all installed Python framework bin dirs to PATH so pip-audit is findable
for _pybin in /Library/Frameworks/Python.framework/Versions/*/bin; do
  export PATH="$PATH:$_pybin"
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

add_finding() {
  local severity="$1"
  local title; title=$(html_escape "$2")
  local desc;  desc=$(html_escape "$3")
  local fix="${4:-}"
  local fix_html=""
  [[ -n "$fix" ]] && fix_html="<div class=\"fix\">$(html_escape "$fix")</div>"
  # Re-allow <br> that we built internally (list entries)
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
      ${fix_html}
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

echo "Starting security scan on ${MACHINE_NAME}..."

# ── 1. macOS Security Settings ────────────────────────────────────────────────
echo "[1/9] macOS security settings..."

SIP=$(csrutil status 2>/dev/null || true)
if printf '%s' "$SIP" | grep -q "enabled"; then
  add_finding "ok" "System Integrity Protection (SIP) — Enabled" "SIP is active, protecting core OS files."
else
  add_finding "critical" "System Integrity Protection (SIP) — DISABLED" \
    "SIP is off. Core OS files can be modified by any process." \
    "Boot into Recovery Mode → csrutil enable"
fi

FV=$(fdesetup status 2>/dev/null || true)
if printf '%s' "$FV" | grep -q "On"; then
  add_finding "ok" "FileVault disk encryption — On" "Full-disk encryption is active."
else
  add_finding "high" "FileVault — OFF" \
    "Disk is not encrypted. Physical access gives full data access." \
    "System Settings → Privacy and Security → FileVault → Turn On"
fi

FW=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || true)
if printf '%s' "$FW" | grep -q "enabled"; then
  add_finding "ok" "Application Firewall — Enabled" "Incoming connections are filtered."
else
  add_finding "critical" "Application Firewall — DISABLED" \
    "All apps can accept incoming connections without restriction. Open ports are exposed to your local network." \
    "System Settings → Network → Firewall → Turn On"
fi

GK=$(spctl --status 2>/dev/null || true)
if printf '%s' "$GK" | grep -q "enabled"; then
  add_finding "ok" "Gatekeeper — Enabled" "Unsigned/unnotarized apps are blocked."
else
  add_finding "high" "Gatekeeper — DISABLED" \
    "Unsigned apps can run without warning." \
    "sudo spctl --master-enable"
fi

# ── 2. Open Ports ─────────────────────────────────────────────────────────────
echo "[2/9] Checking open ports..."

LISTENING=$(lsof -iTCP -sTCP:LISTEN -nP 2>/dev/null | grep -v "^COMMAND" || true)
PUBLIC_PORTS=$(printf '%s' "$LISTENING" | grep "\*:" | awk '{print $9, $1}' | sort -u || true)

if [[ -n "$PUBLIC_PORTS" ]]; then
  PORT_LIST=""
  while IFS= read -r line; do
    PORT_LIST+="• $(html_escape "$line")<br>"
  done <<< "$PUBLIC_PORTS"
  add_finding "medium" "Ports listening on all interfaces (0.0.0.0 / *)" \
    "Reachable from your local network. Enable the firewall to restrict access.<br>${PORT_LIST}" \
    "Enable Firewall — or disable unused services (e.g. AirPlay Receiver)"
else
  add_finding "ok" "No ports exposed on all interfaces" "All listening services are bound to localhost only."
fi

# ── 3. LaunchAgents / LaunchDaemons ───────────────────────────────────────────
echo "[3/9] Checking auto-run agents..."

NON_APPLE_AGENTS=""
for dir in "$HOME/Library/LaunchAgents" "/Library/LaunchAgents" "/Library/LaunchDaemons"; do
  if [[ -d "$dir" ]]; then
    while IFS= read -r -d '' plist; do
      name=$(basename "$plist")
      if [[ "$name" != com.apple.* ]]; then
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
  add_finding "low" "Non-Apple LaunchAgents / LaunchDaemons found" \
    "Review these for anything unexpected:<br>${AGENT_LIST}" \
    "launchctl unload ~/Library/LaunchAgents/NAME.plist"
else
  add_finding "ok" "No unexpected LaunchAgents found" "Only Apple system agents detected."
fi

# ── 4. SSH Config ─────────────────────────────────────────────────────────────
echo "[4/9] Checking SSH..."

if [[ -f "$HOME/.ssh/authorized_keys" ]] && [[ -s "$HOME/.ssh/authorized_keys" ]]; then
  KEY_COUNT=$(wc -l < "$HOME/.ssh/authorized_keys" | tr -d ' ')
  add_finding "high" "SSH authorized_keys has ${KEY_COUNT} entry/entries" \
    "Remote SSH login is possible with stored keys. Verify all are intentional." \
    "Review: cat ~/.ssh/authorized_keys"
else
  add_finding "ok" "No SSH authorized_keys" "Remote SSH login via key auth is not configured."
fi

if [[ -d "$HOME/.ssh" ]]; then
  SSH_PERMS=$(stat -f "%Lp" "$HOME/.ssh" 2>/dev/null || echo "000")
  if [[ "$SSH_PERMS" != "700" ]]; then
    add_finding "medium" "~/.ssh directory permissions are ${SSH_PERMS} (should be 700)" \
      "Loose permissions can expose private keys to other users." "chmod 700 ~/.ssh"
  else
    add_finding "ok" "~/.ssh permissions are correct (700)" "SSH directory is owner-only."
  fi
fi

# ── 5. /etc/hosts ─────────────────────────────────────────────────────────────
echo "[5/9] Checking /etc/hosts..."

SUSPICIOUS_HOSTS=$(grep -Ev "^#|^[[:space:]]*$|localhost|broadcasthost|ip6|\.local$" /etc/hosts 2>/dev/null || true)
if [[ -n "$SUSPICIOUS_HOSTS" ]]; then
  HOST_LIST=""
  while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    HOST_LIST+="• $(html_escape "$entry")<br>"
  done <<< "$SUSPICIOUS_HOSTS"
  add_finding "medium" "Non-standard /etc/hosts entries found" \
    "These could redirect traffic or indicate a hijack:<br>${HOST_LIST}" \
    "Review and remove suspicious lines from /etc/hosts"
else
  add_finding "ok" "/etc/hosts — clean" "No suspicious redirects found."
fi

# ── 6. Shell Profile Secrets ──────────────────────────────────────────────────
echo "[6/9] Scanning shell profiles for secrets..."

SECRET_HITS=0
for f in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.zprofile" "$HOME/.profile"; do
  if [[ -f "$f" ]]; then
    count=$(grep -iE "(api.?key|secret|token|password)\s*=" "$f" 2>/dev/null | grep -cv "^#" || true)
    (( SECRET_HITS += count )) || true
  fi
done

if [[ "$SECRET_HITS" -gt 0 ]]; then
  add_finding "high" "${SECRET_HITS} possible secret(s) found in shell profile" \
    "API keys or tokens may be hardcoded in your shell startup files." \
    "Move secrets to Keychain: security add-generic-password -a \$USER -s NAME -w VALUE"
else
  add_finding "ok" "No hardcoded secrets in shell profiles" "No API keys or tokens found in shell startup files."
fi

# ── 7. Homebrew Outdated Packages ─────────────────────────────────────────────
echo "[7/9] Checking Homebrew..."

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
    add_finding "medium" "${SEC_COUNT} security-relevant Homebrew package(s) outdated" \
      "$PKG_LIST" "$UPGRADE_CMD"
  else
    add_finding "ok" "No security-critical Homebrew packages outdated" "All security-relevant brew packages are current."
  fi

  if [[ "$ALL_COUNT" -gt 0 ]]; then
    add_finding "low" "${ALL_COUNT} total Homebrew package(s) outdated" \
      "Non-critical packages also need updates." "brew upgrade"
  fi
else
  add_finding "low" "Homebrew not found" "Could not check for outdated packages."
fi

# ── 8. Python pip audit ───────────────────────────────────────────────────────
echo "[8/9] Running pip audit..."

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
    add_finding "high" "${VULN_COUNT} Python package CVE(s) found" \
      "$VULN_LIST" "pip install --upgrade ${PKGS}"
  else
    add_finding "ok" "No Python package CVEs found" "pip-audit found no known vulnerabilities."
  fi
else
  add_finding "low" "pip-audit not installed" \
    "Python package CVE scan was skipped." \
    "pip install pip-audit  (then re-run this scan)"
fi

# ── 9. Crontab ────────────────────────────────────────────────────────────────
echo "[9/9] Checking crontab..."

CRON=$(crontab -l 2>/dev/null | grep -Ev "^#|^[[:space:]]*$" || true)
if [[ -n "$CRON" ]]; then
  CRON_LIST=""
  while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    CRON_LIST+="• $(html_escape "$entry")<br>"
  done <<< "$CRON"
  add_finding "medium" "Crontab entries found" \
    "Review these scheduled tasks:<br>${CRON_LIST}" \
    "crontab -e  to edit"
else
  add_finding "ok" "No crontab entries" "No scheduled cron tasks found."
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
<title>Mac Security Report</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #0f1117; color: #e2e8f0; line-height: 1.6; padding: 2rem 1rem; }
  .container { max-width: 860px; margin: 0 auto; }
  h1 { font-size: 1.6rem; font-weight: 700; margin-bottom: 0.25rem; }
  .subtitle { color: #64748b; font-size: 0.875rem; margin-bottom: 2rem; }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .stat-card { background: #1e2130; border-radius: 10px; padding: 1.25rem 1.5rem; border-left: 4px solid; }
  .stat-card.red    { border-color: #ef4444; }
  .stat-card.orange { border-color: #f97316; }
  .stat-card.yellow { border-color: #eab308; }
  .stat-card.blue   { border-color: #3b82f6; }
  .stat-card.green  { border-color: #22c55e; }
  .stat-card .label { font-size: 0.72rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; }
  .stat-card .value { font-size: 2rem; font-weight: 700; margin-top: 0.2rem; }
  .stat-card.red .value    { color: #f87171; }
  .stat-card.orange .value { color: #fb923c; }
  .stat-card.yellow .value { color: #facc15; }
  .stat-card.blue .value   { color: #60a5fa; }
  .stat-card.green .value  { color: #4ade80; }
  section { margin-bottom: 2rem; }
  h2 { font-size: 0.85rem; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 0.75rem; border-bottom: 1px solid #1e2130; padding-bottom: 0.4rem; }
  .item { background: #1e2130; border-radius: 8px; padding: 0.9rem 1.1rem; margin-bottom: 0.5rem; display: flex; align-items: flex-start; gap: 0.75rem; }
  .badge { flex-shrink: 0; font-size: 0.68rem; font-weight: 700; padding: 0.2rem 0.5rem; border-radius: 4px; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 0.15rem; }
  .badge.critical { background: #7f1d1d; color: #fca5a5; }
  .badge.high     { background: #7c2d12; color: #fdba74; }
  .badge.medium   { background: #713f12; color: #fde68a; }
  .badge.low      { background: #1e3a5f; color: #93c5fd; }
  .badge.ok       { background: #14532d; color: #86efac; }
  .item-content .title { font-weight: 600; font-size: 0.95rem; }
  .item-content .desc  { color: #94a3b8; font-size: 0.85rem; margin-top: 0.25rem; }
  .item-content .fix   { color: #4ade80; font-size: 0.8rem; margin-top: 0.35rem; font-family: "SF Mono", monospace; background: #0f1117; padding: 0.3rem 0.6rem; border-radius: 4px; display: inline-block; word-break: break-all; }
  footer { margin-top: 3rem; color: #334155; font-size: 0.8rem; text-align: center; }
</style>
</head>
<body>
<div class="container">
  <h1>Mac Security Report</h1>
  <p class="subtitle">Host: <strong>$(html_escape "$MACHINE_NAME")</strong> &nbsp;·&nbsp; Scanned: <strong>${REPORT_DATE}</strong> &nbsp;·&nbsp; macOS ${MACOS_VER}</p>

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

  <footer>mac-security-scan.sh &nbsp;·&nbsp; ${REPORT_DATE} &nbsp;·&nbsp; This file is deleted from disk automatically after viewing.</footer>
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
