#!/usr/bin/env bash
# =============================================================================
#  duo-wazuh-install.sh
#  Forward Cisco Duo logs (authentication, activity, telephony) into a
#  self-hosted Wazuh manager using Duo's official DuoLogSync, with a tested
#  Wazuh ruleset and NIST 800-171 / CMMC group tags.
#
#  Run ON the Wazuh manager as root (Ubuntu/Debian or RHEL-family).
#
#  Author : Farmhouse Networking - https://www.farmhousenetworking.com
#  License: MIT
#  Repo   : https://github.com/FarmhouseNetworking/Duo-Wazuh-LogSync
# =============================================================================
#
#  Configuration can be supplied three ways (later wins):
#    1. Defaults below
#    2. Environment variables (DUO_IKEY, DUO_SKEY, DUO_API_HOST, ...)
#    3. Command-line flags (--ikey, --skey, --api-host, ...)
#
#  Run with --help for usage.
# =============================================================================

set -uo pipefail

SCRIPT_VERSION="1.0.0"

# ----------------------------- CONFIGURATION ---------------------------------
DUO_IKEY="${DUO_IKEY:-}"                          # Admin API integration key (DI...)
DUO_SKEY="${DUO_SKEY:-}"                          # Admin API secret key
DUO_API_HOST="${DUO_API_HOST:-}"                  # api-xxxxxxxx.duosecurity.com
DUO_ENDPOINTS="${DUO_ENDPOINTS:-auth,telephony,activity}"  # auth,telephony,activity,trustmonitor
DLS_OFFSET_DAYS="${DLS_OFFSET_DAYS:-180}"         # Backfill on first run (max 180)
WAZUH_PORT="${WAZUH_PORT:-5140}"                  # Local-only TCP syslog listener
DLS_GIT_REF="${DLS_GIT_REF:-master}"              # DuoLogSync branch/tag to install
ACTION="${ACTION:-install}"                       # install | resend | status | uninstall
# -----------------------------------------------------------------------------

OSSEC_DIR="/var/ossec"
OSSEC_CONF="$OSSEC_DIR/etc/ossec.conf"
RULES_FILE="$OSSEC_DIR/etc/rules/9999_duo_rules.xml"
DLS_HOME="/opt/duologsync"
DLS_USER="duologsync"
DLS_LOG_DIR="/var/log/duologsync"
DLS_REPO="https://github.com/duosecurity/duo_log_sync.git"
UNIT_FILE="/etc/systemd/system/duologsync.service"
MARK_BEGIN="<!-- BEGIN duo-wazuh-install listener -->"
MARK_END="<!-- END duo-wazuh-install listener -->"
BACKUP_DIR="/root/duo-wazuh-backup-$(date +%Y%m%d-%H%M%S)"

log()  { echo "[$(date '+%H:%M:%S')] $*"; }
ok()   { echo "[$(date '+%H:%M:%S')] OK    $*"; }
warn() { echo "[$(date '+%H:%M:%S')] WARN  $*"; }
die()  { echo "[$(date '+%H:%M:%S')] ERROR $*"; exit 1; }

usage() {
cat <<EOF
duo-wazuh-install.sh v$SCRIPT_VERSION

Usage: sudo ./duo-wazuh-install.sh [action] [options]

Actions:
  install      (default) Install/upgrade DuoLogSync, listener, rules and service
  resend       Clear DuoLogSync checkpoints and re-pull the backfill window
  status       Show service, connection and Duo alert counts
  uninstall    Remove service, listener and rules (keeps /opt/duologsync unless --purge)

Options:
  --ikey KEY           Duo Admin API integration key        (env DUO_IKEY)
  --skey KEY           Duo Admin API secret key             (env DUO_SKEY)
  --api-host HOST      api-xxxxxxxx.duosecurity.com         (env DUO_API_HOST)
  --endpoints LIST     auth,telephony,activity,trustmonitor (env DUO_ENDPOINTS)
  --offset-days N      Backfill days on first run, max 180  (env DLS_OFFSET_DAYS)
  --port N             Local listener port, default 5140    (env WAZUH_PORT)
  --purge              With uninstall: also delete /opt/duologsync and its user
  -h, --help           Show this help

Example:
  sudo DUO_SKEY='xxxx' ./duo-wazuh-install.sh --ikey DIXXXXXXXXXXXXXXXXXX \\
       --api-host api-1234abcd.duosecurity.com
EOF
}

PURGE="no"
# ------------------------------ ARGUMENTS ------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    install|resend|status|uninstall) ACTION="$1" ;;
    --ikey)        DUO_IKEY="${2:-}"; shift ;;
    --skey)        DUO_SKEY="${2:-}"; shift ;;
    --api-host)    DUO_API_HOST="${2:-}"; shift ;;
    --endpoints)   DUO_ENDPOINTS="${2:-}"; shift ;;
    --offset-days) DLS_OFFSET_DAYS="${2:-}"; shift ;;
    --port)        WAZUH_PORT="${2:-}"; shift ;;
    --purge)       PURGE="yes" ;;
    -h|--help)     usage; exit 0 ;;
    *) usage; die "Unknown argument: $1" ;;
  esac
  shift
done

# ------------------------------ HELPERS --------------------------------------
wazuh_group() { getent group wazuh >/dev/null && echo wazuh || echo ossec; }

port_listening() { ss -ltn 2>/dev/null | grep -q "127.0.0.1:${WAZUH_PORT} "; }

wait_for_listener() {
  for _ in $(seq 1 45); do port_listening && return 0; sleep 2; done
  return 1
}

restart_manager() {
  log "Restarting wazuh-manager..."
  systemctl restart wazuh-manager || return 1
  wait_for_listener
}

validate_wazuh() {
  local out
  out="$("$OSSEC_DIR/bin/wazuh-analysisd" -t 2>&1)"
  if echo "$out" | grep -qiE 'ERROR|CRITICAL'; then
    echo "$out" | grep -iE 'ERROR|CRITICAL'
    return 1
  fi
  return 0
}

rollback() {
  warn "Rolling back Wazuh changes from $BACKUP_DIR"
  [[ -f "$BACKUP_DIR/ossec.conf" ]] && cp -p "$BACKUP_DIR/ossec.conf" "$OSSEC_CONF"
  if [[ -f "$BACKUP_DIR/9999_duo_rules.xml" ]]; then
    cp -p "$BACKUP_DIR/9999_duo_rules.xml" "$RULES_FILE"
  else
    rm -f "$RULES_FILE"
  fi
  systemctl restart wazuh-manager || true
}

remove_listener_block() {
  python3 - "$OSSEC_CONF" "$MARK_BEGIN" "$MARK_END" <<'PY'
import sys, re
p, b, e = sys.argv[1:4]
s = open(p).read()
s2 = re.sub(r'[ \t]*' + re.escape(b) + r'.*?' + re.escape(e) + r'[ \t]*\n?', '', s, flags=re.S)
if s2 != s:
    open(p, 'w').write(s2)
    print("removed")
PY
}

# ------------------------------ PREFLIGHT ------------------------------------
[[ $EUID -eq 0 ]] || die "Run as root (sudo)."
[[ -x "$OSSEC_DIR/bin/wazuh-analysisd" && -f "$OSSEC_CONF" ]] || die "Wazuh manager not found in $OSSEC_DIR. Run this on the Wazuh manager."
command -v python3 >/dev/null || die "python3 is required."
command -v systemctl >/dev/null || die "systemd is required."

# ------------------------------ STATUS ---------------------------------------
do_status() {
  echo "=== duologsync service ==="; systemctl is-active duologsync || true
  echo "=== listener / connection on $WAZUH_PORT ==="; ss -tnp 2>/dev/null | grep ":$WAZUH_PORT" || echo "(none)"
  echo "=== last DuoLogSync activity ==="
  grep -E 'ERROR|wrote|adding' "$DLS_LOG_DIR/duologsync.log" 2>/dev/null | tail -6 || echo "(no log)"
  echo "=== Duo alerts today by rule ==="
  grep '"groups":\["duo' "$OSSEC_DIR/logs/alerts/alerts.json" 2>/dev/null \
    | grep -o '"id":"120[0-9]*"' | sort | uniq -c || echo "(none)"
}

# ------------------------------ RESEND ---------------------------------------
do_resend() {
  systemctl stop duologsync 2>/dev/null || true
  rm -f "$DLS_HOME"/checkpoints/*.txt
  systemctl start duologsync || die "duologsync failed to start"
  ok "Checkpoints cleared; DuoLogSync will re-pull up to $DLS_OFFSET_DAYS days on its first fetch (~2 min)."
  warn "Frequency rules (e.g. 120004) use arrival time, so backfilled events can trip them. Ignore backfill-time hits."
}

# ------------------------------ UNINSTALL ------------------------------------
do_uninstall() {
  mkdir -p "$BACKUP_DIR"; cp -p "$OSSEC_CONF" "$BACKUP_DIR/"
  systemctl disable --now duologsync 2>/dev/null || true
  rm -f "$UNIT_FILE" /etc/systemd/system/wazuh-manager.service.wants/duologsync.service
  systemctl daemon-reload
  rm -f "$RULES_FILE"
  remove_listener_block >/dev/null
  validate_wazuh || { rollback; die "Validation failed after removal - restored backup."; }
  systemctl restart wazuh-manager
  if [[ "$PURGE" == "yes" ]]; then
    rm -rf "$DLS_HOME" "$DLS_LOG_DIR"
    userdel "$DLS_USER" 2>/dev/null || true
    ok "Purged $DLS_HOME and user $DLS_USER"
  fi
  ok "Uninstalled. ossec.conf backup: $BACKUP_DIR"
}

# ------------------------------ INSTALL --------------------------------------
do_install() {
  # --- validate inputs ---
  [[ -n "$DUO_IKEY" && -n "$DUO_SKEY" && -n "$DUO_API_HOST" ]] || die "DUO_IKEY, DUO_SKEY and DUO_API_HOST are required (see --help)."
  [[ "$DUO_IKEY" =~ ^DI[A-Z0-9]{18}$ ]] || die "DUO_IKEY does not look like a Duo integration key (DI + 18 chars)."
  [[ "$DUO_API_HOST" =~ ^api-[a-z0-9]+\.(duosecurity|duofederal)\.com$ ]] || die "DUO_API_HOST must look like api-xxxxxxxx.duosecurity.com"
  [[ "$WAZUH_PORT" =~ ^[0-9]+$ && "$WAZUH_PORT" -ge 1 && "$WAZUH_PORT" -le 65535 ]] || die "Invalid WAZUH_PORT"
  [[ "$DLS_OFFSET_DAYS" =~ ^[0-9]+$ && "$DLS_OFFSET_DAYS" -ge 1 && "$DLS_OFFSET_DAYS" -le 180 ]] || die "DLS_OFFSET_DAYS must be 1-180"

  # DuoLogSync 2.4.x accepts only these endpoints. 'adminaction' was retired;
  # admin actions now arrive via 'activity'.
  local ep ep_yaml=""
  IFS=',' read -ra EPS <<< "${DUO_ENDPOINTS// /}"
  for ep in "${EPS[@]}"; do
    [[ "$ep" =~ ^(auth|telephony|activity|trustmonitor)$ ]] || die "Unsupported endpoint '$ep' (use auth, telephony, activity, trustmonitor)."
    ep_yaml+="'$ep', "
  done
  ep_yaml="[${ep_yaml%, }]"

  # --- network checks ---
  local code
  code="$(curl -s -o /dev/null -m 15 -w '%{http_code}' "https://$DUO_API_HOST" || true)"
  [[ "$code" != "000" && -n "$code" ]] || die "Cannot reach https://$DUO_API_HOST (outbound 443 blocked?)."
  ok "Duo API reachable (HTTP $code)"

  if ss -ltnp 2>/dev/null | grep -q ":${WAZUH_PORT} " && ! ss -ltnp 2>/dev/null | grep ":${WAZUH_PORT} " | grep -q wazuh-remoted; then
    die "Port $WAZUH_PORT is in use by another process. Choose another with --port."
  fi

  # Rule ID collision check (120000-120039) in other custom rule files
  local clash
  clash="$(grep -lE 'id="1200[0-3][0-9]"' "$OSSEC_DIR"/etc/rules/*.xml 2>/dev/null | grep -v "$(basename "$RULES_FILE")" || true)"
  [[ -z "$clash" ]] || die "Rule IDs 120000-120039 already used in: $clash"

  # --- packages ---
  log "Installing prerequisites..."
  if command -v apt-get >/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q git python3-venv curl >/dev/null || die "apt-get install failed"
  elif command -v dnf >/dev/null; then
    dnf install -y -q git python3 curl >/dev/null || die "dnf install failed"
  elif command -v yum >/dev/null; then
    yum install -y -q git python3 curl >/dev/null || die "yum install failed"
  else
    die "Unsupported package manager (need apt, dnf or yum)."
  fi

  # --- DuoLogSync ---
  id "$DLS_USER" >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin -d "$DLS_HOME" "$DLS_USER"
  mkdir -p "$DLS_HOME/checkpoints" "$DLS_LOG_DIR"
  if [[ -d "$DLS_HOME/src/.git" ]]; then
    log "Updating DuoLogSync source..."
    # safe.directory: the tree is owned by the duologsync user, git runs as root
    local g=(git -c "safe.directory=$DLS_HOME/src" -C "$DLS_HOME/src")
    { "${g[@]}" fetch -q --all && "${g[@]}" checkout -q "$DLS_GIT_REF" \
      && { "${g[@]}" pull -q --ff-only 2>/dev/null || true; }; } || warn "git update failed - keeping installed version"
  else
    log "Cloning DuoLogSync..."
    git clone -q "$DLS_REPO" "$DLS_HOME/src" || die "git clone failed"
    git -C "$DLS_HOME/src" checkout -q "$DLS_GIT_REF" || die "Unknown DLS_GIT_REF $DLS_GIT_REF"
  fi
  [[ -x "$DLS_HOME/venv/bin/python" ]] || python3 -m venv "$DLS_HOME/venv" || die "venv creation failed"
  "$DLS_HOME/venv/bin/pip" install -q --disable-pip-version-check --upgrade "$DLS_HOME/src" || die "pip install of DuoLogSync failed"
  ok "DuoLogSync $("$DLS_HOME/venv/bin/pip" show duologsync 2>/dev/null | awk '/^Version/{print $2}') installed"

  # --- DuoLogSync config (single quotes required by DLS) ---
  umask 077
  cat > "$DLS_HOME/config.yml" <<EOF
version: '1.0.0'
dls_settings:
  log_filepath: '$DLS_LOG_DIR/duologsync.log'
  log_format: 'JSON'
  api:
    offset: $DLS_OFFSET_DAYS
    timeout: 120
  checkpointing:
    enabled: True
    directory: '$DLS_HOME/checkpoints'
servers:
  - id: 'wazuh'
    hostname: '127.0.0.1'
    port: $WAZUH_PORT
    protocol: 'TCP'
account:
  ikey: '$DUO_IKEY'
  skey: '$DUO_SKEY'
  hostname: '$DUO_API_HOST'
  endpoint_server_mappings:
    - endpoints: $ep_yaml
      server: 'wazuh'
  is_msp: False
EOF
  umask 022
  chown -R "$DLS_USER:$DLS_USER" "$DLS_HOME" "$DLS_LOG_DIR"
  chmod 600 "$DLS_HOME/config.yml"
  ok "Config written to $DLS_HOME/config.yml (mode 600)"

  # --- Backup Wazuh files ---
  mkdir -p "$BACKUP_DIR"
  cp -p "$OSSEC_CONF" "$BACKUP_DIR/"
  [[ -f "$RULES_FILE" ]] && cp -p "$RULES_FILE" "$BACKUP_DIR/"
  ok "Backups in $BACKUP_DIR"

  # --- Local-only syslog listener (idempotent, marker-delimited) ---
  remove_listener_block >/dev/null
  if grep -qE "<port>[[:space:]]*${WAZUH_PORT}[[:space:]]*</port>" "$OSSEC_CONF"; then
    rollback; die "ossec.conf already has another <remote> on port $WAZUH_PORT. Use --port."
  fi
  python3 - "$OSSEC_CONF" "$WAZUH_PORT" "$MARK_BEGIN" "$MARK_END" <<'PY' || { rollback; die "Failed to edit ossec.conf"; }
import sys
p, port, b, e = sys.argv[1:5]
s = open(p).read()
block = f"""  {b}
  <remote>
    <connection>syslog</connection>
    <port>{port}</port>
    <protocol>tcp</protocol>
    <local_ip>127.0.0.1</local_ip>
    <allowed-ips>127.0.0.1</allowed-ips>
  </remote>
  {e}
"""
i = s.find('</ossec_config>')
if i < 0:
    sys.exit(2)
open(p, 'w').write(s[:i] + block + s[i:])
PY
  ok "Listener 127.0.0.1:$WAZUH_PORT/tcp added to ossec.conf"

  # --- Rules ---
  write_rules
  chown "root:$(wazuh_group)" "$RULES_FILE" 2>/dev/null || true; chmod 660 "$RULES_FILE"
  ok "Rules written to $RULES_FILE"

  # --- Validate, restart, verify listener ---
  if ! validate_wazuh; then rollback; die "wazuh-analysisd -t failed - changes rolled back."; fi
  ok "Wazuh configuration and rules validated"
  restart_manager || { rollback; die "Listener on $WAZUH_PORT did not come up - changes rolled back."; }
  ok "wazuh-remoted listening on 127.0.0.1:$WAZUH_PORT"

  # --- systemd unit ---
  # DuoLogSync opens ONE TCP connection at start and never reconnects. A
  # wazuh-manager restart silently kills it (the next batch is lost, then DLS
  # exits). PartOf= ties DLS restarts to the manager; ExecStartPre waits for
  # the listener so DLS never connects to nothing.
  cat > "$UNIT_FILE" <<EOF
[Unit]
Description=Duo Log Sync to Wazuh
After=network-online.target wazuh-manager.service
Wants=network-online.target
PartOf=wazuh-manager.service

[Service]
User=$DLS_USER
ExecStartPre=/bin/bash -c 'for i in \$(seq 1 60); do ss -ltn | grep -q "127.0.0.1:$WAZUH_PORT " && exit 0; sleep 2; done; exit 1'
ExecStart=$DLS_HOME/venv/bin/duologsync $DLS_HOME/config.yml
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target wazuh-manager.service
EOF
  systemctl daemon-reload
  systemctl reenable duologsync >/dev/null 2>&1 || systemctl enable duologsync >/dev/null 2>&1
  systemctl restart duologsync || die "duologsync failed to start - check: journalctl -u duologsync"
  sleep 15

  # --- Verify ---
  local fail=0
  if systemctl is-active --quiet duologsync; then ok "duologsync service active"; else warn "duologsync not active"; fail=1; fi
  if ss -tnp 2>/dev/null | grep ":$WAZUH_PORT" | grep -q duologsync; then ok "DuoLogSync connected to remoted"; else warn "No DuoLogSync connection on $WAZUH_PORT yet"; fail=1; fi
  if grep -qE 'ERROR' "$DLS_LOG_DIR/duologsync.log" 2>/dev/null; then
    warn "Errors in DuoLogSync log:"; grep ERROR "$DLS_LOG_DIR/duologsync.log" | tail -3; fail=1
  fi
  logtest_check '{"access_device":{"ip":"203.0.113.10","hostname":"TEST-PC"},"application":{"name":"Microsoft RDP"},"event_type":"authentication","factor":"duo_push","isotimestamp":"2026-01-01T00:00:00+00:00","reason":"user_approved","result":"success","timestamp":1767225600,"txid":"00000000-0000-0000-0000-000000000000","user":{"name":"logtest"},"eventtype":"authentication"}' 120001 "auth success" || fail=1
  logtest_check '{"action":{"details":null,"name":"admin_login"},"activity_id":"00000000-0000-0000-0000-000000000000","actor":{"name":"logtest","type":"admin"},"outcome":{"result":"SUCCESS"},"target":{"type":"admin_login"},"ts":"2026-01-01T00:00:00+00:00"}' 120030 "activity" || fail=1

  echo
  if [[ $fail -eq 0 ]]; then
    ok "INSTALL COMPLETE. First Duo fetch runs ~2 minutes after start. Backfill: $DLS_OFFSET_DAYS days."
  else
    warn "INSTALL FINISHED WITH WARNINGS - review output above."
  fi
  echo "Check later with: sudo $0 status"
  return $fail
}

logtest_check() {
  local sample="$1" want="$2" label="$3" out
  out="$(echo "$sample" | "$OSSEC_DIR/bin/wazuh-logtest" 2>&1)"
  if echo "$out" | grep -q "id: '$want'"; then
    ok "wazuh-logtest: sample $label event matched rule $want"
    return 0
  fi
  warn "wazuh-logtest: sample $label event did NOT match $want. Got: $(echo "$out" | grep -m1 "id: '" | xargs)"
  return 1
}

write_rules() {
cat > "$RULES_FILE" <<'EOF'
<!--
  Duo Security rules for Wazuh (DuoLogSync JSON over local syslog)
  https://github.com/FarmhouseNetworking/Duo-Wazuh-LogSync

  IMPORTANT: Duo auth JSON contains both "timestamp" and "event_type", so the
  stock Suricata rule 86600 (level 0) claims it first and the event dies there.
  Auth parents therefore attach under 86600 (120000) with a standalone fallback
  (120009). The 9999_ filename makes this file load AFTER the stock ruleset so
  if_sid 86600 resolves.

  "action" is a Wazuh static field - never use <field name="action">.
-->
<group name="duo,">

  <!-- ===== Authentication log ===== -->
  <rule id="120000" level="0">
    <if_sid>86600</if_sid>
    <field name="txid">\.+</field>
    <field name="factor">\.+</field>
    <description>Duo: authentication event</description>
  </rule>

  <rule id="120009" level="0">
    <decoded_as>json</decoded_as>
    <field name="txid">\.+</field>
    <field name="factor">\.+</field>
    <description>Duo: authentication event</description>
  </rule>

  <rule id="120001" level="3">
    <if_sid>120000, 120009</if_sid>
    <field name="result">^success$</field>
    <description>Duo: auth success - $(user.name) to $(application.name) via $(factor)</description>
    <group>authentication_success,nist_800_171_3.5.3,</group>
  </rule>

  <rule id="120002" level="5">
    <if_sid>120000, 120009</if_sid>
    <field name="result">^denied$|^failure$|^error$</field>
    <description>Duo: auth denied - $(user.name) to $(application.name) ($(reason))</description>
    <group>authentication_failed,nist_800_171_3.5.3,</group>
  </rule>

  <rule id="120003" level="12">
    <if_sid>120000, 120009</if_sid>
    <field name="result">^fraud$</field>
    <description>Duo: user reported push as FRAUD - $(user.name) from $(access_device.ip)</description>
    <group>authentication_failed,mfa_fraud,nist_800_171_3.14.6,</group>
  </rule>

  <!-- Note: frequency windows use ARRIVAL time; a backfill can trip this. -->
  <rule id="120004" level="10" frequency="5" timeframe="300">
    <if_matched_sid>120002</if_matched_sid>
    <same_field>user.name</same_field>
    <description>Duo: 5+ denied auths in 5 min for $(user.name) - possible MFA fatigue/brute force</description>
    <group>authentication_failures,nist_800_171_3.1.8,</group>
  </rule>

  <rule id="120005" level="8">
    <if_sid>120000, 120009</if_sid>
    <field name="factor">bypass_code|remembered_device</field>
    <field name="result">^success$</field>
    <description>Duo: auth via $(factor) for $(user.name) - verify expected</description>
  </rule>

  <!-- ===== Activity log (admin panel, config changes, directory sync) ===== -->
  <rule id="120030" level="3">
    <decoded_as>json</decoded_as>
    <field name="activity_id">\.+</field>
    <field name="action.name">\.+</field>
    <description>Duo activity: $(actor.name) ($(actor.type)) - $(action.name) on $(target.type) $(target.name) [$(outcome.result)]</description>
    <group>duo_activity,nist_800_171_3.3.1,</group>
  </rule>

  <rule id="120031" level="5">
    <if_sid>120030</if_sid>
    <field name="action.name">^admin_login</field>
    <field name="outcome.result">FAIL</field>
    <description>Duo admin panel: FAILED login by $(actor.name) from $(access_device.ip.address)</description>
    <group>duo_activity,authentication_failed,nist_800_171_3.1.8,</group>
  </rule>

  <rule id="120032" level="10" frequency="3" timeframe="300">
    <if_matched_sid>120031</if_matched_sid>
    <same_field>actor.name</same_field>
    <description>Duo admin panel: 3+ failed logins in 5 min for $(actor.name)</description>
    <group>duo_activity,authentication_failures,nist_800_171_3.1.8,</group>
  </rule>

  <rule id="120033" level="10">
    <if_sid>120030</if_sid>
    <field name="action.name">bypass|admin_create|admin_delete|admin_update|admin_role|integration_create|integration_delete|integration_update|policy|user_delete|settings|trusted|directory_sync</field>
    <description>Duo config change: $(action.name) by $(actor.name) on $(target.type) $(target.name)</description>
    <group>duo_activity,config_changed,nist_800_171_3.4.3,nist_800_171_3.1.7,</group>
  </rule>

  <rule id="120034" level="8">
    <if_sid>120030</if_sid>
    <field name="action.name">^ad_sync_finish$</field>
    <field name="outcome.result">FAIL</field>
    <description>Duo: AD directory sync FAILED - disabled/removed AD users may remain active in Duo</description>
    <group>duo_activity,account_management,nist_800_171_3.1.1,nist_800_171_3.5.6,</group>
  </rule>

  <!-- ===== Telephony log (credit usage; low value, unverified field match) ===== -->
  <rule id="120020" level="2">
    <if_sid>86600</if_sid>
    <field name="context">\.+</field>
    <field name="credits">\.+</field>
    <description>Duo telephony: $(type) to $(phone) ($(context))</description>
  </rule>

  <rule id="120021" level="2">
    <decoded_as>json</decoded_as>
    <field name="context">\.+</field>
    <field name="credits">\.+</field>
    <description>Duo telephony: $(type) to $(phone) ($(context))</description>
  </rule>

</group>
EOF
}

# ------------------------------ MAIN -----------------------------------------
log "duo-wazuh-install v$SCRIPT_VERSION - action: $ACTION"
case "$ACTION" in
  install)   do_install ;;
  resend)    do_resend ;;
  status)    do_status ;;
  uninstall) do_uninstall ;;
  *) usage; die "Unknown action $ACTION" ;;
esac
