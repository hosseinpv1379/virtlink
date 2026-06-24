#!/usr/bin/env bash
# virlink — kernel tunnel manager  (setup & management)
# https://github.com/hosseinpv1379/virtlink
set -euo pipefail

# ── constants ─────────────────────────────────────────────────────────────────
GITHUB_REPO="hosseinpv1379/virtlink"
INSTALL_DIR="/opt/virlink"
VIRLINK_BIN="${INSTALL_DIR}/virlink"
CONFIGS_DIR="${INSTALL_DIR}/configs"
LOGS_DIR="/var/log/virlink"
SCRIPT_VERSION="2.5.0"

UPDATE_AVAILABLE=0
LATEST_TAG=""
LAST_CFG_PATH=""   # set by gen_* instead of echoing (avoids $() capture)
PICKED_TUNNEL=""   # set by pick_tunnel (avoids printf -v scope bug with set -u)

# ── colors ────────────────────────────────────────────────────────────────────
R='\033[0;31m' G='\033[0;32m' Y='\033[0;33m'
B='\033[0;34m' C='\033[0;36m' W='\033[1;37m'
DIM='\033[2m' BOLD='\033[1m' NC='\033[0m'

# ── I/O helpers ───────────────────────────────────────────────────────────────
tty_out()  { printf '%b'   "$@" > /dev/tty; }
tty_line() { printf '%b\n' "$@" > /dev/tty; }

info()  { echo -e "  ${C}→${NC} $*"; }
ok()    { echo -e "  ${G}✓${NC} $*"; }
warn()  { echo -e "  ${Y}⚠${NC} $*"; }
err()   { echo -e "  ${R}✗${NC} $*" >&2; }
die()   { err "$*"; exit 1; }
blank() { echo; }
sep()   { echo -e "${DIM}────────────────────────────────────────────────${NC}"; }

confirm() {
  tty_out "  ${W}?${NC} $1 [y/N]: "
  read -r ans < /dev/tty
  [[ "${ans,,}" == "y" ]]
}

prompt() {
  local var="$1" msg="$2" def="${3:-}"
  if [[ -n "$def" ]]; then
    tty_out "  ${W}?${NC} $msg ${DIM}[$def]${NC}: "
  else
    tty_out "  ${W}?${NC} $msg: "
  fi
  local val
  read -r val < /dev/tty
  if [[ -z "$val" && -n "$def" ]]; then
    printf -v "$var" '%s' "$def"
  else
    printf -v "$var" '%s' "$val"
  fi
}

pick() {
  local var="$1"; shift
  local title="$1"; shift
  local opts=("$@")
  tty_line
  tty_line "  ${W}${title}${NC}"
  tty_line "${DIM}────────────────────────────────────────────────${NC}"
  local i
  for i in "${!opts[@]}"; do
    tty_out "    ${C}$(printf '%2d' $((i+1)))${NC}  ${opts[$i]}\n"
  done
  tty_line
  local n
  while true; do
    tty_out "  ${W}?${NC} Choose [1-${#opts[@]}]: "
    read -r n < /dev/tty
    if [[ "$n" =~ ^[0-9]+$ ]] && (( n >= 1 && n <= ${#opts[@]} )); then
      printf -v "$var" '%s' "${opts[$((n-1))]}"
      return
    fi
    tty_line "  ${Y}⚠${NC} Invalid choice, try again."
  done
}

press_enter() {
  tty_out "  Press Enter to continue..."
  read -r < /dev/tty || true
}

# ── safe download helper ──────────────────────────────────────────────────────
# Downloads URL to DEST using a temp file (avoids partial-write failures).
# curl error 23 = cannot write to destination — solved by writing to /tmp first.
safe_download() {
  local url="$1" dest="$2"
  local tmp
  tmp=$(mktemp /tmp/virlink.XXXXXX) || die "mktemp failed"
  if ! curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 10 "$url" -o "$tmp"; then
    rm -f "$tmp"
    die "Download failed: $url"
  fi
  mv "$tmp" "$dest"
}

# ── auto-install ──────────────────────────────────────────────────────────────
_is_piped_install() {
  [[ "$0" == /dev/fd/* ]] || [[ "$0" == /proc/self/fd/* ]] || \
  [[ ! -f "$VIRLINK_BIN" ]]
}

do_install() {
  echo -e "\n${BOLD}${B}  virlink installer${NC}\n"
  [[ $EUID -eq 0 ]] || die "Installer requires root.  Re-run: sudo bash <(curl ...)"

  echo -e "  ${C}→${NC} Creating ${INSTALL_DIR}..."
  mkdir -p "${INSTALL_DIR}/configs" || die "Cannot create ${INSTALL_DIR}"

  echo -e "  ${C}→${NC} Downloading virlink binary..."
  safe_download \
    "https://github.com/${GITHUB_REPO}/releases/latest/download/virlink" \
    "${INSTALL_DIR}/virlink"
  chmod +x "${INSTALL_DIR}/virlink"

  echo -e "  ${C}→${NC} Downloading setup script..."
  safe_download \
    "https://github.com/${GITHUB_REPO}/releases/latest/download/setup.sh" \
    "${INSTALL_DIR}/setup.sh"
  chmod +x "${INSTALL_DIR}/setup.sh"

  # symlinks in PATH
  ln -sf "${INSTALL_DIR}/virlink"  /usr/local/bin/virlink      2>/dev/null || true
  ln -sf "${INSTALL_DIR}/setup.sh" /usr/local/bin/virlink-setup 2>/dev/null || true

  local ver
  ver=$("${INSTALL_DIR}/virlink" --version 2>/dev/null || echo "?")
  echo -e "  ${G}✓${NC} ${BOLD}${ver}${NC} installed to ${INSTALL_DIR}"
  echo -e "  ${G}✓${NC} Commands: ${W}virlink-setup${NC}  ${W}virlink${NC}"
  echo
  exec "${INSTALL_DIR}/setup.sh"
}

# ── version / update ──────────────────────────────────────────────────────────
check_update() {
  local current latest
  set +e
  current=$("$VIRLINK_BIN" --version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' || echo "")
  latest=$(curl -fsSL --connect-timeout 2 --max-time 4 \
    "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" 2>/dev/null | \
    python3 -c "import sys,json; print(json.load(sys.stdin).get('tag_name',''))" 2>/dev/null || echo "")
  set -e
  LATEST_TAG="$latest"
  if [[ -n "$latest" && -n "$current" && "${latest#v}" != "${current#v}" ]]; then
    UPDATE_AVAILABLE=1
  else
    UPDATE_AVAILABLE=0
  fi
}

do_self_update() {
  require_root
  [[ -z "$LATEST_TAG" ]] && { info "Checking latest release..."; check_update; }
  if (( ! UPDATE_AVAILABLE )); then
    ok "Already up to date."
    blank; press_enter; return
  fi
  info "Downloading virlink ${LATEST_TAG}..."
  safe_download "https://github.com/${GITHUB_REPO}/releases/latest/download/virlink" \
    "${VIRLINK_BIN}.new"
  chmod +x "${VIRLINK_BIN}.new"
  mv "${VIRLINK_BIN}.new" "$VIRLINK_BIN"

  info "Updating setup script..."
  safe_download "https://github.com/${GITHUB_REPO}/releases/latest/download/setup.sh" \
    "${INSTALL_DIR}/setup.sh.new"
  chmod +x "${INSTALL_DIR}/setup.sh.new"
  mv "${INSTALL_DIR}/setup.sh.new" "${INSTALL_DIR}/setup.sh"

  ok "Updated to ${LATEST_TAG} — restarting..."
  blank
  exec "${INSTALL_DIR}/setup.sh"
}

# ── header ────────────────────────────────────────────────────────────────────
header() {
  clear
  echo -e "${BOLD}${B}"
  echo "  ██╗   ██╗██╗██████╗ ██╗     ██╗███╗   ██╗██╗  ██╗"
  echo "  ██║   ██║██║██╔══██╗██║     ██║████╗  ██║██║ ██╔╝"
  echo "  ██║   ██║██║██████╔╝██║     ██║██╔██╗ ██║█████╔╝ "
  echo "  ╚██╗ ██╔╝██║██╔══██╗██║     ██║██║╚██╗██║██╔═██╗ "
  echo "   ╚████╔╝ ██║██║  ██║███████╗██║██║ ╚████║██║  ██╗"
  echo "    ╚═══╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝"
  echo -e "${NC}"
  local cur_ver
  cur_ver=$("$VIRLINK_BIN" --version 2>/dev/null | grep -oE 'v[0-9.]+' || echo "?")
  if (( UPDATE_AVAILABLE )); then
    echo -e "  ${DIM}${cur_ver}${NC}   ${Y}${BOLD}⬆  ${LATEST_TAG} available${NC}  ${DIM}(option 6)${NC}"
  else
    echo -e "  ${DIM}${cur_ver}  ✓ up to date${NC}"
  fi
  blank
}

# ── prerequisites ─────────────────────────────────────────────────────────────
require_root() { [[ $EUID -eq 0 ]] || die "Requires root — run: sudo virlink-setup"; }
require_bin()  { [[ -x "$VIRLINK_BIN" ]] || die "Binary not found: $VIRLINK_BIN"; }
ensure_dirs()  { mkdir -p "$CONFIGS_DIR" "$LOGS_DIR"; }

# ── systemd service helpers ───────────────────────────────────────────────────
svc_name()       { echo "virlink-${1}"; }
svc_unit()       { echo "/etc/systemd/system/virlink-${1}.service"; }
svc_log()        { echo "${LOGS_DIR}/${1}.log"; }

# tunnel_is_running: checks systemd active state (fallback: log last 5s activity)
tunnel_is_running() {
  systemctl is-active "$(svc_name "$1")" &>/dev/null
}

# write_service_file: creates /etc/systemd/system/virlink-<name>.service
write_service_file() {
  local name="$1"
  local cfg="${CONFIGS_DIR}/${name}.toml"
  local log; log="$(svc_log "$name")"
  local svc; svc="$(svc_unit "$name")"
  mkdir -p "$LOGS_DIR"
  cat > "$svc" << EOF
[Unit]
Description=virlink tunnel — ${name}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${VIRLINK_BIN} -c ${cfg}
Restart=on-failure
RestartSec=10
StandardOutput=append:${log}
StandardError=append:${log}

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
}

# tunnel_start: creates service, enables + starts it
tunnel_start() {
  local name="$1"
  local cfg="${CONFIGS_DIR}/${name}.toml"
  [[ -f "$cfg" ]] || die "Config not found: $cfg"
  write_service_file "$name"
  local svc; svc="$(svc_name "$name")"
  info "Enabling service ${svc}..."
  systemctl enable "$svc" 2>/dev/null
  info "Starting ${svc}..."
  systemctl start "$svc"
  sleep 1
  if tunnel_is_running "$name"; then
    ok "Tunnel '${name}' running  (service: ${svc})"
    ok "Log: $(svc_log "$name")"
    ok "Control: systemctl {start|stop|restart|status} ${svc}"
  else
    err "Failed to start '${name}'. Check log:"
    journalctl -u "$svc" -n 20 --no-pager 2>/dev/null || tail -20 "$(svc_log "$name")" 2>/dev/null || true
  fi
}

# tunnel_remove: full purge — service, journal, log file, config
tunnel_remove() {
  local name="$1"
  local svc; svc="$(svc_name "$name")"
  local unit; unit="$(svc_unit "$name")"
  local log; log="$(svc_log "$name")"
  local cfg="${CONFIGS_DIR}/${name}.toml"

  info "Stopping service ${svc}..."
  systemctl stop    "$svc" 2>/dev/null || true
  systemctl disable "$svc" 2>/dev/null || true

  info "Removing service unit ${unit}..."
  rm -f "$unit"
  systemctl daemon-reload 2>/dev/null || true
  systemctl reset-failed  "$svc" 2>/dev/null || true

  # purge journal entries for this unit
  info "Purging journal for ${svc}..."
  if journalctl --unit="$svc" --disk-usage &>/dev/null; then
    # rotate + flush so the latest journal file is writable, then vacuum
    journalctl --rotate 2>/dev/null || true
    # remove journal entries older than 1s (effectively all) for the unit.
    # journalctl doesn't support per-unit vacuum, so we use --vacuum-time
    # on the flush file that was just rotated — this only removes sealed files.
    journalctl --vacuum-time=1s 2>/dev/null || true
  fi

  info "Removing log file ${log}..."
  rm -f "$log"

  info "Removing config ${cfg}..."
  rm -f "$cfg"

  ok "Tunnel '${name}' completely removed."
  blank
}

# tunnel_stop: stops + disables service
tunnel_stop() {
  local name="$1"
  local svc; svc="$(svc_name "$name")"
  if ! systemctl list-unit-files "${svc}.service" &>/dev/null && \
     ! [[ -f "$(svc_unit "$name")" ]]; then
    warn "No service file found for '${name}'."
  fi
  info "Stopping ${svc}..."
  systemctl stop    "$svc" 2>/dev/null || true
  systemctl disable "$svc" 2>/dev/null || true
  ok "Tunnel '${name}' stopped and disabled."
}

# tunnel_status: shows systemctl status + colorized binary log tail
tunnel_status() {
  local name="$1"
  local cfg="${CONFIGS_DIR}/${name}.toml"
  local svc; svc="$(svc_name "$name")"
  local log; log="$(svc_log "$name")"

  # colorize INF/WRN/ERR/heartbeat lines
  _clog() {
    sed -E \
      -e "s/  INF  /  $(printf '\033[90m')·$(printf '\033[0m')  /g" \
      -e "s/  WRN  /  $(printf '\033[33m')⚠$(printf '\033[0m')  /g" \
      -e "s/  ERR  /  $(printf '\033[1;31m')✗$(printf '\033[0m')  /g" \
      -e "s/  DBG  /  $(printf '\033[36m')·$(printf '\033[0m')  /g" \
      -e "s/(♥)/$(printf '\033[32m')\1$(printf '\033[0m')/g" \
      -e "s/\bconnected\b/$(printf '\033[32m')connected$(printf '\033[0m')/g" \
      -e "s/\bdegraded\b/$(printf '\033[33m')degraded$(printf '\033[0m')/g" \
      -e "s/\bdead\b/$(printf '\033[31m')dead$(printf '\033[0m')/g" \
      -e "s/\blink=UP\b/link=$(printf '\033[32m')UP$(printf '\033[0m')/g" \
      -e "s/\blink=DOWN\b/link=$(printf '\033[31m')DOWN$(printf '\033[0m')/g"
  }

  blank
  echo -e "  ${BOLD}${C}⬡  ${name}${NC}"
  sep

  # ── service state ──────────────────────────────────────────────
  local running=0
  if tunnel_is_running "$name"; then
    running=1
    echo -e "  ${G}${BOLD}● RUNNING${NC}  ${DIM}(${svc})${NC}"
  else
    echo -e "  ${R}● STOPPED${NC}  ${DIM}(${svc})${NC}"
  fi

  # ── config summary ─────────────────────────────────────────────
  if [[ -f "$cfg" ]]; then
    local type mode local_ip remote_ip cidr
    type=$(grep -E '^\s*type\s*='      "$cfg" 2>/dev/null | head -1 | awk -F'"' '{print $2}')
    mode=$(grep -E '^\s*mode\s*='      "$cfg" 2>/dev/null | head -1 | awk -F'"' '{print $2}')
    local_ip=$(grep -E '^\s*local_ip'  "$cfg" 2>/dev/null | head -1 | awk -F'"' '{print $2}')
    remote_ip=$(grep -E '^\s*remote_ip' "$cfg" 2>/dev/null | head -1 | awk -F'"' '{print $2}')
    cidr=$(grep -E '^\s*cidr'          "$cfg" 2>/dev/null | head -1 | awk -F'"' '{print $2}')
    blank
    echo -e "  ${DIM}type${NC}     ${Y}${type}${NC}   ${DIM}mode${NC}  ${mode}"
    echo -e "  ${DIM}local${NC}    ${local_ip}  ${DIM}→${NC}  ${remote_ip}"
    echo -e "  ${DIM}overlay${NC}  ${C}${cidr}${NC}"
    echo -e "  ${DIM}config${NC}   ${DIM}${cfg}${NC}"
  fi

  # ── systemd stats ──────────────────────────────────────────────
  blank
  echo -e "  ${DIM}── systemd ──────────────────────────────────────${NC}"
  systemctl status "$svc" --no-pager -l --lines=0 2>/dev/null | \
    grep -E '(Loaded|Active|Main PID|Tasks|Memory|CPU)' | sed 's/^/  /' || true

  # ── binary log tail (colorized) ────────────────────────────────
  blank
  echo -e "  ${DIM}── binary log (last 30 lines) ───────────────────${NC}"
  if [[ -f "$log" ]] && [[ -s "$log" ]]; then
    tail -30 "$log" | _clog | sed 's/^/  /'
    echo -e "  ${DIM}↳ ${log}${NC}"
  else
    if (( running )); then
      echo -e "  ${DIM}(reading from journal)${NC}"
      journalctl -u "$svc" -n 20 --no-pager 2>/dev/null | tail -20 | _clog | sed 's/^/  /'
    else
      echo -e "  ${DIM}(no log yet — start the tunnel first)${NC}"
    fi
  fi
  blank
}

# ── numbered tunnel picker ────────────────────────────────────────────────────
# pick_tunnel — shows numbered list, sets PICKED_TUNNEL global.
# Returns 1 if no tunnels exist.
pick_tunnel() {
  PICKED_TUNNEL=""
  local cfgs=()
  mapfile -t cfgs < <(find "$CONFIGS_DIR" -maxdepth 1 -name "*.toml" 2>/dev/null | sort)
  if [[ ${#cfgs[@]} -eq 0 ]]; then
    tty_line "  ${Y}⚠${NC} No tunnels configured yet."
    return 1
  fi
  tty_line
  tty_line "  ${BOLD}Tunnels:${NC}"
  tty_line "${DIM}────────────────────────────────────────────────${NC}"
  local i cfg _tname _type _icon
  for i in "${!cfgs[@]}"; do
    cfg="${cfgs[$i]}"
    _tname=$(basename "$cfg" .toml)
    _type=$(grep 'type ' "$cfg" 2>/dev/null | head -1 | awk -F'"' '{print $2}' || echo "?")
    if tunnel_is_running "$_tname"; then
      _icon="${G}●${NC}"
    else
      _icon="${R}●${NC}"
    fi
    tty_out "    ${C}$(printf '%2d' $((i+1)))${NC}  $(printf '%b' "$_icon")  ${BOLD}${_tname}${NC}  ${DIM}(${_type})${NC}\n"
  done
  tty_line
  local n
  while true; do
    tty_out "  ${W}?${NC} Choose [1-${#cfgs[@]}]: "
    read -r n < /dev/tty
    if [[ "$n" =~ ^[0-9]+$ ]] && (( n >= 1 && n <= ${#cfgs[@]} )); then
      PICKED_TUNNEL="$(basename "${cfgs[$((n-1))]}" .toml)"
      return 0
    fi
    tty_line "  ${Y}⚠${NC} Invalid choice."
  done
}

# list_tunnels: display only (no selection)
list_tunnels() {
  local cfgs=()
  mapfile -t cfgs < <(find "$CONFIGS_DIR" -maxdepth 1 -name "*.toml" 2>/dev/null | sort)
  if [[ ${#cfgs[@]} -eq 0 ]]; then
    warn "No tunnels configured yet."
    return 1
  fi
  blank
  printf "  ${BOLD}%-4s %-26s %-18s %-10s %s${NC}\n" "#" "NAME" "TYPE" "STATUS" "REMOTE"
  sep
  local i cfg name type remote status
  for i in "${!cfgs[@]}"; do
    cfg="${cfgs[$i]}"
    name=$(basename "$cfg" .toml)
    type=$(grep 'type '    "$cfg" 2>/dev/null | head -1 | awk -F'"' '{print $2}')
    remote=$(grep 'remote_ip' "$cfg" 2>/dev/null | awk -F'"' '{print $2}')
    if tunnel_is_running "$name"; then
      status="${G}running${NC}"
    else
      status="${R}stopped${NC}"
    fi
    printf "  ${C}%-4s${NC}%-26s %-18s " "$((i+1))" "$name" "$type"
    echo -e "${status}   ${remote}"
  done
  blank
}

# ── config helpers ────────────────────────────────────────────────────────────
collect_base_inputs() {
  local _n _m _l _r _c
  blank
  prompt _n "Tunnel name (e.g. kharej-gre)" ""
  [[ -z "$_n" ]] && die "Name cannot be empty."
  _n="${_n// /-}"
  pick _m "Mode" "client" "server"
  blank
  prompt _l "This server's public IP"    ""
  prompt _r "Peer server's public IP"    ""
  prompt _c "Overlay subnet (CIDR)"      "10.20.10.0/24"
  printf -v "$1" '%s' "$_n"
  printf -v "$2" '%s' "$_m"
  printf -v "$3" '%s' "$_l"
  printf -v "$4" '%s' "$_r"
  printf -v "$5" '%s' "$_c"
}

write_transport() {
  cat >> "$1" << EOF

[transport]
port               = $2
proto              = "$3"
heartbeat_interval = $4
EOF
}

write_transport_no_port() {
  cat >> "$1" << EOF

[transport]
heartbeat_interval = $2
EOF
}

write_tuning() {
  local file="$1" multipath="${2:-false}"
  cat >> "$file" << EOF

[tuning]
bbr          = true
multipath    = ${multipath}
channel_size = 10_000

[logging]
level = "info"

[health]
disabled = false
port     = 6543
EOF
}

add_forward_section() {
  local cfg="$1" mode="$2"
  if [[ "$mode" == "client" ]]; then
    cat >> "$cfg" << 'EOF'

# ── port forwarding (client only) ─────────────────────────────────────────────
[forward]
enabled = false
rules   = [
  # "1000:2000",    # :1000 → peer:2000
  # "8080:80/tcp",
]
EOF
  fi
}

# ── config generators ─────────────────────────────────────────────────────────
gen_gre_fou() {
  local name mode local_ip remote_ip cidr port mtu cfg
  collect_base_inputs name mode local_ip remote_ip cidr
  prompt port "FOU UDP port" "5556"
  prompt mtu  "MTU"          "1420"
  cfg="${CONFIGS_DIR}/${name}.toml"
  cat > "$cfg" << EOF
# virlink — ${name}
[tunnel]
type      = "gre-fou"
mode      = "${mode}"
local_ip  = "${local_ip}"
remote_ip = "${remote_ip}"
cidr      = "${cidr}"
mtu       = ${mtu}
EOF
  write_transport "$cfg" "$port" "fou" "10"
  write_tuning    "$cfg"
  add_forward_section "$cfg" "$mode"
  LAST_CFG_PATH="$cfg"
}

gen_ipip_fou() {
  local name mode local_ip remote_ip cidr port mtu cfg
  collect_base_inputs name mode local_ip remote_ip cidr
  prompt port "FOU UDP port" "5055"
  prompt mtu  "MTU"          "1440"
  cfg="${CONFIGS_DIR}/${name}.toml"
  cat > "$cfg" << EOF
# virlink — ${name}
[tunnel]
type      = "ipip-fou"
mode      = "${mode}"
local_ip  = "${local_ip}"
remote_ip = "${remote_ip}"
cidr      = "${cidr}"
mtu       = ${mtu}
EOF
  write_transport "$cfg" "$port" "fou" "10"
  write_tuning    "$cfg"
  add_forward_section "$cfg" "$mode"
  LAST_CFG_PATH="$cfg"
}

gen_bonded() {
  local name mode local_ip remote_ip cidr port1 port2 mtu cfg
  collect_base_inputs name mode local_ip remote_ip cidr
  prompt port1 "Path-1 FOU port" "5557"
  prompt port2 "Path-2 FOU port" "5558"
  prompt mtu   "MTU"             "1400"
  cfg="${CONFIGS_DIR}/${name}.toml"
  cat > "$cfg" << EOF
# virlink — ${name}
[tunnel]
type      = "bonded-gre-fou"
mode      = "${mode}"
local_ip  = "${local_ip}"
remote_ip = "${remote_ip}"
cidr      = "${cidr}"
mtu       = ${mtu}

[transport]
port               = ${port1}
port2              = ${port2}
proto              = "fou"
heartbeat_interval = 10
EOF
  write_tuning "$cfg" "true"
  add_forward_section "$cfg" "$mode"
  LAST_CFG_PATH="$cfg"
}

gen_l2tpv3() {
  local name mode local_ip remote_ip cidr port mtu cfg
  collect_base_inputs name mode local_ip remote_ip cidr
  prompt port "UDP port" "5059"
  prompt mtu  "MTU"      "1464"
  cfg="${CONFIGS_DIR}/${name}.toml"
  cat > "$cfg" << EOF
# virlink — ${name}
[tunnel]
type      = "l2tpv3"
mode      = "${mode}"
local_ip  = "${local_ip}"
remote_ip = "${remote_ip}"
cidr      = "${cidr}"
mtu       = ${mtu}

[transport]
port               = ${port}
proto              = "l2tp"
heartbeat_interval = 10

[l2tp]
client_tunnel_id  = 1000
server_tunnel_id  = 2000
client_session_id = 1000
server_session_id = 2000
EOF
  write_tuning "$cfg"
  add_forward_section "$cfg" "$mode"
  LAST_CFG_PATH="$cfg"
}

gen_gre_wg() {
  local name mode local_ip remote_ip cidr port mtu cfg
  local cpriv cpub spriv spub
  collect_base_inputs name mode local_ip remote_ip cidr
  prompt port "WireGuard port" "51820"
  prompt mtu  "MTU"            "1380"
  blank
  warn "Run 'virlink keygen' to generate WireGuard key pairs."
  prompt cpriv "Client private key" ""
  prompt cpub  "Client public key"  ""
  prompt spriv "Server private key" ""
  prompt spub  "Server public key"  ""
  cfg="${CONFIGS_DIR}/${name}.toml"
  cat > "$cfg" << EOF
# virlink — ${name}
[tunnel]
type      = "gre-wg"
mode      = "${mode}"
local_ip  = "${local_ip}"
remote_ip = "${remote_ip}"
cidr      = "${cidr}"
mtu       = ${mtu}

[transport]
port               = ${port}
proto              = "wireguard"
heartbeat_interval = 10

[wireguard]
client_private_key = "${cpriv}"
client_public_key  = "${cpub}"
server_private_key = "${spriv}"
server_public_key  = "${spub}"

[security]
encryption = true
EOF
  write_tuning "$cfg"
  add_forward_section "$cfg" "$mode"
  LAST_CFG_PATH="$cfg"
}

gen_udp_obfs() {
  local name mode local_ip remote_ip cidr port mtu key mask_val mask padding cfg
  collect_base_inputs name mode local_ip remote_ip cidr
  prompt port "UDP port (443 recommended)" "443"
  prompt mtu  "MTU"                        "1400"
  blank
  tty_line "  ${W}Obfuscation settings${NC}"
  sep
  prompt key "Shared secret key (same on both sides)" ""
  [[ -z "$key" ]] && die "Key cannot be empty."
  pick mask_val "Mask mode" \
    "noise  — pure random ciphertext (no header)" \
    "quic   — fake QUIC v1 header on port 443  (recommended for Iran)" \
    "dtls   — fake DTLS 1.2 header"
  mask="${mask_val%% *}"
  if confirm "Enable random padding (defeats length analysis)"; then
    padding="true"
  else
    padding="false"
  fi
  cfg="${CONFIGS_DIR}/${name}.toml"
  cat > "$cfg" << EOF
# virlink — ${name}
[tunnel]
type      = "udp-obfs"
mode      = "${mode}"
local_ip  = "${local_ip}"
remote_ip = "${remote_ip}"
cidr      = "${cidr}"
mtu       = ${mtu}

[transport]
port               = ${port}
proto              = "udp-obfs"
heartbeat_interval = 10

[obfs]
key     = "${key}"
mask    = "${mask}"
padding = ${padding}

[security]
encryption = true
EOF
  write_tuning "$cfg"
  add_forward_section "$cfg" "$mode"
  LAST_CFG_PATH="$cfg"
}

gen_ipsec() {
  local name mode local_ip remote_ip cidr port mtu cfg
  local spiout spiin encout encin authout authin rh32
  collect_base_inputs name mode local_ip remote_ip cidr
  prompt port "FOU port" "5556"
  prompt mtu  "MTU"      "1380"
  blank
  warn "Generate random keys with:"
  warn "  python3 -c \"import os; print('0x'+os.urandom(32).hex())\""
  prompt spiout  "SPI outbound"  "0x00000001"
  prompt spiin   "SPI inbound"   "0x00000002"
  rh32=$(openssl rand -hex 32 2>/dev/null || echo "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
  prompt encout  "Enc key out"   "0x${rh32}"
  rh32=$(openssl rand -hex 32 2>/dev/null || echo "2f2e2d2c2b2a29282726252423222120201f1e1d1c1b1a191817161514131211")
  prompt encin   "Enc key in"    "0x${rh32}"
  rh32=$(openssl rand -hex 32 2>/dev/null || echo "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2")
  prompt authout "Auth key out"  "0x${rh32}"
  rh32=$(openssl rand -hex 32 2>/dev/null || echo "b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1")
  prompt authin  "Auth key in"   "0x${rh32}"
  cfg="${CONFIGS_DIR}/${name}.toml"
  cat > "$cfg" << EOF
# virlink — ${name}
[tunnel]
type      = "gre-fou-ipsec"
mode      = "${mode}"
local_ip  = "${local_ip}"
remote_ip = "${remote_ip}"
cidr      = "${cidr}"
mtu       = ${mtu}

[transport]
port               = ${port}
proto              = "fou"
heartbeat_interval = 10

[security]
encryption   = true
spi_out      = "${spiout}"
spi_in       = "${spiin}"
enc_key_out  = "${encout}"
enc_key_in   = "${encin}"
auth_key_out = "${authout}"
auth_key_in  = "${authin}"
EOF
  write_tuning "$cfg"
  add_forward_section "$cfg" "$mode"
  LAST_CFG_PATH="$cfg"
}

gen_gre() {
  local name mode local_ip remote_ip cidr mtu cfg
  collect_base_inputs name mode local_ip remote_ip cidr
  prompt mtu "MTU" "1476"
  cfg="${CONFIGS_DIR}/${name}.toml"
  cat > "$cfg" << EOF
# virlink — ${name}  (kernel GRE, IP proto 47)
[tunnel]
type      = "gre"
mode      = "${mode}"
local_ip  = "${local_ip}"
remote_ip = "${remote_ip}"
cidr      = "${cidr}"
mtu       = ${mtu}
EOF
  write_transport_no_port "$cfg" "10"
  write_tuning "$cfg"
  add_forward_section "$cfg" "$mode"
  LAST_CFG_PATH="$cfg"
}

gen_tcp() {
  local name mode local_ip remote_ip cidr port mtu cfg
  collect_base_inputs name mode local_ip remote_ip cidr
  prompt port "TCP port" "8443"
  prompt mtu  "MTU"      "1400"
  cfg="${CONFIGS_DIR}/${name}.toml"
  cat > "$cfg" << EOF
# virlink — ${name}  (user-space TCP tunnel)
[tunnel]
type      = "tcp"
mode      = "${mode}"
local_ip  = "${local_ip}"
remote_ip = "${remote_ip}"
cidr      = "${cidr}"
mtu       = ${mtu}
EOF
  write_transport "$cfg" "$port" "tcp" "10"
  write_tuning    "$cfg"
  add_forward_section "$cfg" "$mode"
  LAST_CFG_PATH="$cfg"
}

gen_udp() {
  local name mode local_ip remote_ip cidr port mtu cfg
  collect_base_inputs name mode local_ip remote_ip cidr
  prompt port "UDP port" "5060"
  prompt mtu  "MTU"      "1440"
  cfg="${CONFIGS_DIR}/${name}.toml"
  cat > "$cfg" << EOF
# virlink — ${name}  (user-space UDP tunnel, no encryption)
[tunnel]
type      = "udp"
mode      = "${mode}"
local_ip  = "${local_ip}"
remote_ip = "${remote_ip}"
cidr      = "${cidr}"
mtu       = ${mtu}
EOF
  write_transport "$cfg" "$port" "udp" "10"
  write_tuning    "$cfg"
  add_forward_section "$cfg" "$mode"
  LAST_CFG_PATH="$cfg"
}

gen_icmp() {
  local name mode local_ip remote_ip cidr mtu cfg
  collect_base_inputs name mode local_ip remote_ip cidr
  prompt mtu "MTU" "1472"
  blank
  warn "ICMP tunnel requires CAP_NET_RAW (root). Firewall must allow proto 1."
  cfg="${CONFIGS_DIR}/${name}.toml"
  cat > "$cfg" << EOF
# virlink — ${name}  (ICMP Echo tunnel, IP proto 1)
[tunnel]
type      = "icmp"
mode      = "${mode}"
local_ip  = "${local_ip}"
remote_ip = "${remote_ip}"
cidr      = "${cidr}"
mtu       = ${mtu}
EOF
  write_transport_no_port "$cfg" "10"
  write_tuning "$cfg"
  add_forward_section "$cfg" "$mode"
  LAST_CFG_PATH="$cfg"
}

gen_bip() {
  local name mode local_ip remote_ip cidr mtu cfg
  collect_base_inputs name mode local_ip remote_ip cidr
  prompt mtu "MTU" "1480"
  blank
  warn "BIP uses IP protocol 58 for DPI evasion. Requires root + firewall allow proto 58."
  cfg="${CONFIGS_DIR}/${name}.toml"
  cat > "$cfg" << EOF
# virlink — ${name}  (BIP tunnel, IP proto 58)
[tunnel]
type      = "bip"
mode      = "${mode}"
local_ip  = "${local_ip}"
remote_ip = "${remote_ip}"
cidr      = "${cidr}"
mtu       = ${mtu}
EOF
  write_transport_no_port "$cfg" "10"
  write_tuning "$cfg"
  add_forward_section "$cfg" "$mode"
  LAST_CFG_PATH="$cfg"
}

# ── screens ───────────────────────────────────────────────────────────────────
screen_create() {
  header
  echo -e "  ${BOLD}Create New Tunnel${NC}"
  sep
  local ttype
  pick ttype "Tunnel type" \
    "gre-fou        — GRE in UDP (FOU)                  fast, no encryption" \
    "ipip-fou       — IPIP in UDP (FOU)                 minimal overhead" \
    "bonded-gre-fou — Dual GRE-FOU ECMP                 2× bandwidth" \
    "l2tpv3         — L2TPv3 over UDP                   Layer-2 tunnel" \
    "gre-wg         — GRE inside WireGuard              encrypted" \
    "udp-obfs       — Obfuscated UDP (AES-256-GCM)      DPI bypass (Iran)" \
    "gre-fou-ipsec  — GRE-FOU + IPsec ESP               encrypted + FOU" \
    "gre            — Kernel GRE (proto 47)             no UDP wrapper" \
    "tcp            — User-space TCP tunnel             auto-reconnect" \
    "udp            — User-space UDP tunnel             plain UDP" \
    "icmp           — ICMP Echo tunnel (proto 1)        DPI bypass" \
    "bip            — BIP tunnel (proto 58)             DPI bypass"
  local key="${ttype%%[[:space:]]*}"

  LAST_CFG_PATH=""
  case "$key" in
    gre-fou)        gen_gre_fou  ;;
    ipip-fou)       gen_ipip_fou ;;
    bonded-gre-fou) gen_bonded   ;;
    l2tpv3)         gen_l2tpv3   ;;
    gre-wg)         gen_gre_wg   ;;
    udp-obfs)       gen_udp_obfs ;;
    gre-fou-ipsec)  gen_ipsec    ;;
    gre)            gen_gre      ;;
    tcp)            gen_tcp      ;;
    udp)            gen_udp      ;;
    icmp)           gen_icmp     ;;
    bip)            gen_bip      ;;
    *) die "Unknown type: $key" ;;
  esac

  blank
  ok "Config saved: ${LAST_CFG_PATH}"
  blank
  echo -e "  ${DIM}Config preview:${NC}"
  sep
  grep -v '^#' "${LAST_CFG_PATH}" | grep -v '^$' | head -28 | sed 's/^/    /'
  blank

  # Auto-install as service and start
  require_root
  ensure_dirs
  local name; name=$(basename "${LAST_CFG_PATH}" .toml)
  info "Installing as systemd service and starting..."
  tunnel_start "$name"

  blank
  press_enter
}

screen_manage() {
  header
  echo -e "  ${BOLD}Manage Tunnels${NC}"
  sep
  ensure_dirs
  if ! pick_tunnel; then
    press_enter
    return
  fi
  local name="$PICKED_TUNNEL"

  blank
  # Show brief status
  local svc; svc="$(svc_name "$name")"
  if tunnel_is_running "$name"; then
    echo -e "  ${G}●${NC} ${BOLD}${name}${NC} is ${G}RUNNING${NC}"
  else
    echo -e "  ${R}●${NC} ${BOLD}${name}${NC} is ${R}STOPPED${NC}"
  fi
  blank

  local action
  pick action "Action" \
    "start    — install service + start" \
    "stop     — stop + disable service" \
    "restart  — restart service" \
    "status   — show status, logs, and systemctl" \
    "edit     — open config in editor" \
    "remove   — delete tunnel + service"
  action="${action%%[[:space:]]*}"

  require_root
  case "$action" in
    start)
      tunnel_start "$name"
      ;;
    stop)
      tunnel_stop "$name"
      ;;
    restart)
      systemctl restart "$(svc_name "$name")" 2>/dev/null || {
        tunnel_stop "$name"
        tunnel_start "$name"
      }
      ok "Restarted."
      ;;
    status)
      tunnel_status "$name"
      ;;
    edit)
      local editor="${EDITOR:-nano}"
      "$editor" "${CONFIGS_DIR}/${name}.toml"
      if confirm "Restart tunnel to apply changes"; then
        systemctl restart "$(svc_name "$name")" 2>/dev/null || true
        ok "Restarted."
      fi
      ;;
    remove)
      if confirm "Completely remove tunnel '${name}' (service + logs + config)"; then
        tunnel_remove "$name"
      fi
      ;;
  esac
  blank
  press_enter
}

screen_setup_forward() {
  header
  echo -e "  ${BOLD}Add Port Forwarding Rule${NC}"
  sep
  ensure_dirs
  if ! pick_tunnel; then
    press_enter
    return
  fi
  local name="$PICKED_TUNNEL"
  local cfg="${CONFIGS_DIR}/${name}.toml"
  blank
  echo -e "  ${W}Format:${NC}  listenPort:targetPort  or  port:port/tcp"
  local rule
  prompt rule "Rule (e.g. 1000:2000)" ""
  [[ -z "$rule" ]] && return
  if grep -q '^\[forward\]' "$cfg"; then
    sed -i "s/^enabled = false/enabled = true/" "$cfg"
    sed -i "/^rules.*=.*\[/a\\  \"${rule}\"," "$cfg"
    ok "Rule added: $rule"
  else
    cat >> "$cfg" << EOF

[forward]
enabled = true
rules   = ["${rule}"]
EOF
    ok "Forward section added: $rule"
  fi
  if tunnel_is_running "$name" && confirm "Restart tunnel to apply"; then
    systemctl restart "$(svc_name "$name")" 2>/dev/null || true
    ok "Restarted."
  fi
  blank
  press_enter
}

screen_logs() {
  header
  echo -e "  ${BOLD}Tunnel Logs${NC}"
  sep
  ensure_dirs
  if ! pick_tunnel; then
    press_enter
    return
  fi
  local name="$PICKED_TUNNEL"
  local log; log="$(svc_log "$name")"
  local svc; svc="$(svc_name "$name")"

  blank
  echo -e "  ${BOLD}${name}${NC}  ${DIM}(${svc})${NC}"
  echo -e "  ${DIM}log: ${log}${NC}"
  blank

  local mode
  pick mode "View mode" \
    "tail-50   — last 50 lines" \
    "follow    — live tail (Ctrl+C to stop)" \
    "search    — grep keyword"
  read -r mode _ <<< "$mode"   # extract first word only

  blank

  # colorizer: INF=dim, WRN=yellow, ERR=red bold, ♥=green, states
  _colorize() {
    sed -E \
      -e "s/ INF / $(printf '\033[90m')INF$(printf '\033[0m') /g" \
      -e "s/ WRN / $(printf '\033[33m')WRN$(printf '\033[0m') /g" \
      -e "s/ ERR / $(printf '\033[1;31m')ERR$(printf '\033[0m') /g" \
      -e "s/ DBG / $(printf '\033[36m')DBG$(printf '\033[0m') /g" \
      -e "s/(♥)/$(printf '\033[32m')\1$(printf '\033[0m')/g" \
      -e "s/(connected)/$(printf '\033[32m')\1$(printf '\033[0m')/g" \
      -e "s/(degraded)/$(printf '\033[33m')\1$(printf '\033[0m')/g" \
      -e "s/(dead)/$(printf '\033[1;31m')\1$(printf '\033[0m')/g" \
      -e "s/(UP)/$(printf '\033[32m')\1$(printf '\033[0m')/g" \
      -e "s/(DOWN)/$(printf '\033[31m')\1$(printf '\033[0m')/g"
  }

  case "$mode" in
    tail-50)
      if [[ -f "$log" && -s "$log" ]]; then
        echo -e "${DIM}──── last 50 lines ─────────────────────────────${NC}"
        tail -50 "$log" | _colorize
        sep
      else
        warn "Log file empty or not found: $log"
        if systemctl is-active "$svc" &>/dev/null; then
          blank
          echo -e "  ${DIM}journalctl output:${NC}"
          journalctl -u "$svc" -n 50 --no-pager 2>/dev/null | _colorize | tail -50
        fi
      fi
      ;;
    follow)
      echo -e "  ${Y}⚠${NC}  Press ${BOLD}Ctrl+C${NC} to stop following"
      sep
      if [[ -f "$log" ]]; then
        tail -f "$log" | _colorize
      else
        journalctl -f -u "$svc" 2>/dev/null | _colorize
      fi
      ;;
    search)
      local kw
      prompt kw "Search keyword" ""
      [[ -z "$kw" ]] && return
      blank
      echo -e "  ${DIM}── results for \"${kw}\" ──────────────────────────${NC}"
      if [[ -f "$log" ]]; then
        grep -i "$kw" "$log" | _colorize | tail -100
      else
        journalctl -u "$svc" --no-pager 2>/dev/null | grep -i "$kw" | _colorize | tail -100
      fi
      sep
      ;;
  esac

  blank
  press_enter
}

screen_keygen() {
  header
  echo -e "  ${BOLD}Generate WireGuard Keypair${NC}"
  sep
  require_bin
  blank
  "$VIRLINK_BIN" keygen
  blank
  press_enter
}

screen_update() {
  header
  echo -e "  ${BOLD}Update virlink${NC}"
  sep
  info "Checking GitHub for latest release..."
  check_update
  local cur_ver
  cur_ver=$("$VIRLINK_BIN" --version 2>/dev/null | grep -oE 'v[0-9.]+' || echo "?")
  blank
  echo -e "  Installed : ${W}${cur_ver}${NC}"
  echo -e "  Latest    : ${W}${LATEST_TAG:-unknown}${NC}"
  blank
  if (( UPDATE_AVAILABLE )); then
    if confirm "Update to ${LATEST_TAG}"; then
      do_self_update
    fi
  else
    ok "Already up to date."
  fi
  blank
  press_enter
}

# ── main menu ─────────────────────────────────────────────────────────────────
main() {
  require_bin
  mkdir -p "$CONFIGS_DIR"

  # background version check
  check_update &
  local _bg=$!

  while true; do
    if [[ -n "${_bg:-}" ]]; then
      wait "$_bg" 2>/dev/null || true
      _bg=""
    fi

    header
    echo -e "  ${BOLD}Main Menu${NC}"
    sep
    echo -e "    ${C}1${NC}  Create new tunnel"
    echo -e "    ${C}2${NC}  Manage tunnels  (start / stop / status / restart)"
    echo -e "    ${C}3${NC}  View tunnel logs  (tail / follow / search)"
    echo -e "    ${C}4${NC}  Add port forward rule"
    echo -e "    ${C}5${NC}  List all tunnels"
    echo -e "    ${C}6${NC}  Generate WireGuard keypair"
    if (( UPDATE_AVAILABLE )); then
      echo -e "    ${Y}7${NC}  ${Y}Update available${NC} → ${LATEST_TAG}"
    else
      echo -e "    ${C}7${NC}  Check for updates"
    fi
    echo -e "    ${C}8${NC}  Exit"
    blank
    tty_out "  ${W}?${NC} Choose [1-8]: "
    read -r choice < /dev/tty
    case "$choice" in
      1) screen_create ;;
      2) screen_manage ;;
      3) screen_logs ;;
      4) screen_setup_forward ;;
      5)
        header
        list_tunnels || true
        press_enter
        ;;
      6) screen_keygen ;;
      7) screen_update ;;
      8) blank; ok "Goodbye."; blank; exit 0 ;;
      *) warn "Invalid choice." ;;
    esac
  done
}

# ── entry point ───────────────────────────────────────────────────────────────
if _is_piped_install; then
  [[ $EUID -eq 0 ]] || die "Run as root: sudo bash <(curl ...)"
  do_install
fi

case "${1:-menu}" in
  start)   require_root; ensure_dirs; tunnel_start  "${2:?tunnel name required}" ;;
  stop)    require_root; ensure_dirs; tunnel_stop   "${2:?tunnel name required}" ;;
  restart) require_root; ensure_dirs
           systemctl restart "$(svc_name "${2:?name required}")" 2>/dev/null || \
           { tunnel_stop "${2}"; tunnel_start "${2}"; } ;;
  status)  tunnel_status "${2:?tunnel name required}" ;;
  list)    list_tunnels ;;
  update)  require_root; check_update; do_self_update ;;
  menu)    main ;;
  *)       echo "Usage: $0 [menu|start|stop|restart|status|list|update] [name]"; exit 1 ;;
esac
