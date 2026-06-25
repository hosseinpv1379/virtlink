#!/usr/bin/env bash
# virlink — kernel & userspace tunnel manager  (setup & management)
# https://github.com/hosseinpv1379/virtlink
set -euo pipefail

# ══════════════════════════════════════════════════════════════════════════════
# Constants & paths
# ══════════════════════════════════════════════════════════════════════════════
SCRIPT_VERSION="1.0.0"
GITHUB_REPO="hosseinpv1379/virtlink"
TELEGRAM_CHANNEL="@Gozar_XRay"
TAGLINE="High-performance kernel & userspace tunneling"

INSTALL_DIR="/opt/virlink"
VIRLINK_BIN="${INSTALL_DIR}/virlink"
CONFIGS_DIR="${INSTALL_DIR}/configs"
LOGS_DIR="/var/log/virlink"

UPDATE_AVAILABLE=0
LATEST_TAG=""
LAST_CFG_PATH=""   # set by gen_* instead of echoing (avoids $() capture)
PICKED_TUNNEL=""   # set by pick_tunnel (avoids printf -v scope bug with set -u)
PRESELECTED_MODE=""  # set during create flow (client/server chosen upfront)

# Kernel vs userspace tunnel classification
# Note: vxlan-wg is supported by the binary but has no setup.sh generator yet.
readonly -a KERNEL_TUNNEL_KEYS=(
  gre-fou ipip-fou bonded-gre-fou l2tpv3 gre-wg gre-fou-ipsec gre
)
readonly -a USERSPACE_TUNNEL_KEYS=(
  icmp udp bip tcp udp-obfs
)

# ══════════════════════════════════════════════════════════════════════════════
# UI — colors & formatting
# ══════════════════════════════════════════════════════════════════════════════
R='\033[0;31m' G='\033[0;32m' Y='\033[0;33m'
B='\033[0;34m' C='\033[0;36m' W='\033[1;37m'
DIM='\033[2m' BOLD='\033[1m' NC='\033[0m'

# ══════════════════════════════════════════════════════════════════════════════
# I/O helpers
# ══════════════════════════════════════════════════════════════════════════════
tty_out()  { printf '%b'   "$@" > /dev/tty; }
tty_line() { printf '%b\n' "$@" > /dev/tty; }

info()  { echo -e "  ${C}→${NC} $*"; }
ok()    { echo -e "  ${G}✓${NC} $*"; }
warn()  { echo -e "  ${Y}⚠${NC} $*"; }
err()   { echo -e "  ${R}✗${NC} $*" >&2; }
die()   { err "$*"; exit 1; }
blank() { echo; }
sep()   { echo -e "${DIM}══════════════════════════════════════════════════${NC}"; }
sep_thin() { echo -e "${DIM}────────────────────────────────────────────────${NC}"; }

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
  sep_thin
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

# ══════════════════════════════════════════════════════════════════════════════
# System info helpers
# ══════════════════════════════════════════════════════════════════════════════
core_version() {
  local ver
  ver=$("$VIRLINK_BIN" --version 2>/dev/null | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")
  [[ -n "$ver" && "$ver" != v* ]] && ver="v${ver}"
  echo "${ver:-?}"
}

core_is_installed() {
  [[ -x "$VIRLINK_BIN" ]]
}

detect_public_ip() {
  local ip=""
  ip=$(curl -fsSL --connect-timeout 3 --max-time 5 ifconfig.me 2>/dev/null || true)
  [[ -z "$ip" ]] && ip=$(curl -fsSL --connect-timeout 3 --max-time 5 api.ipify.org 2>/dev/null || true)
  echo "${ip:-}"
}

detect_local_ip() {
  hostname -I 2>/dev/null | awk '{print $1}'
}

detect_ip() {
  local ip
  ip=$(detect_public_ip)
  [[ -n "$ip" ]] && { echo "$ip"; return; }
  ip=$(detect_local_ip)
  echo "${ip:-unknown}"
}

# Sets GEO_LOCATION and GEO_DATACENTER globals (or "null")
fetch_geo_info() {
  GEO_LOCATION="null"
  GEO_DATACENTER="null"
  local ip="${1:-}"
  [[ -z "$ip" || "$ip" == "unknown" ]] && return

  local raw city country isp org status
  raw=$(curl -fsSL --connect-timeout 3 --max-time 5 \
    "http://ip-api.com/json/${ip}?fields=status,city,country,isp,org" 2>/dev/null || echo "")
  [[ -z "$raw" ]] && return

  status=$(echo "$raw" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)
  [[ "$status" != "success" ]] && return

  city=$(echo "$raw"    | grep -o '"city":"[^"]*"'    | head -1 | cut -d'"' -f4)
  country=$(echo "$raw" | grep -o '"country":"[^"]*"' | head -1 | cut -d'"' -f4)
  isp=$(echo "$raw"     | grep -o '"isp":"[^"]*"'     | head -1 | cut -d'"' -f4)
  org=$(echo "$raw"     | grep -o '"org":"[^"]*"'     | head -1 | cut -d'"' -f4)

  [[ -n "$city" || -n "$country" ]] && GEO_LOCATION="${city:-?}, ${country:-?}"
  [[ -n "$org" ]] && GEO_DATACENTER="$org"
  [[ "$GEO_DATACENTER" == "null" && -n "$isp" ]] && GEO_DATACENTER="$isp"
}

# ══════════════════════════════════════════════════════════════════════════════
# Banner
# ══════════════════════════════════════════════════════════════════════════════
show_banner() {
  clear
  echo -e "${BOLD}${C}"
  echo "▗▄▄▖  ▗▄▖  ▗▄▄▖▗▖ ▗▖▗▖ ▗▖ ▗▄▖ ▗▖ ▗▖▗▖"
  echo "▐▌ ▐▌▐▌ ▐▌▐▌   ▐▌▗▞▘▐▌ ▐▌▐▌ ▐▌▐▌ ▐▌▐▌"
  echo "▐▛▀▚▖▐▛▀▜▌▐▌   ▐▛▚▖ ▐▛▀▜▌▐▛▀▜▌▐▌ ▐▌▐▌"
  echo "▐▙▄▞▘▐▌ ▐▌▝▚▄▄▖▐▌ ▐▌▐▌ ▐▌▐▌ ▐▌▝▚▄▞▘▐▙▄▄▖"
  echo -e "${NC}"
  echo -e "  ${DIM}${TAGLINE}${NC}"
  blank

  local core_ver ip geo_loc geo_dc core_state
  core_ver=$(core_version)
  ip=$(detect_ip)
  fetch_geo_info "$ip"
  geo_loc="${GEO_LOCATION:-null}"
  geo_dc="${GEO_DATACENTER:-null}"

  if core_is_installed; then
    core_state="${G}Installed${NC}  ${DIM}(${core_ver})${NC}"
  else
    core_state="${R}Not installed${NC}"
  fi

  echo -e "  ${DIM}Script Version:${NC}   v${SCRIPT_VERSION}"
  echo -e "  ${DIM}Core Version:${NC}     ${core_ver}"
  echo -e "  ${DIM}Telegram Channel:${NC} ${TELEGRAM_CHANNEL}"
  sep
  echo -e "  ${DIM}IP Address:${NC}       ${W}${ip}${NC}"
  if [[ "$geo_loc" != "null" ]]; then
    echo -e "  ${DIM}Location:${NC}         ${geo_loc}"
  fi
  if [[ "$geo_dc" != "null" ]]; then
    echo -e "  ${DIM}Datacenter:${NC}       ${geo_dc}"
  fi
  echo -e "  ${DIM}Virtlink Core:${NC}    ${core_state}"
  sep

  if (( UPDATE_AVAILABLE )); then
    echo -e "  ${Y}${BOLD}⬆  Core update available → ${LATEST_TAG}${NC}  ${DIM}(menu option 4)${NC}"
    blank
  fi
}

# Legacy alias used by a few internal screens
header() { show_banner; }

# ══════════════════════════════════════════════════════════════════════════════
# Download & install
# ══════════════════════════════════════════════════════════════════════════════
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

_is_piped_install() {
  [[ "$0" == /dev/fd/* ]] || [[ "$0" == /proc/self/fd/* ]] || \
  [[ ! -f "$VIRLINK_BIN" ]]
}

do_install() {
  echo -e "\n${BOLD}${B}  virlink installer${NC}\n"
  [[ $EUID -eq 0 ]] || die "Installer requires root.  Re-run: sudo bash <(curl ...)"

  info "Creating ${INSTALL_DIR}..."
  mkdir -p "${INSTALL_DIR}/configs" || die "Cannot create ${INSTALL_DIR}"

  info "Downloading virlink binary..."
  safe_download \
    "https://github.com/${GITHUB_REPO}/releases/latest/download/virlink" \
    "${INSTALL_DIR}/virlink"
  chmod +x "${INSTALL_DIR}/virlink"

  info "Downloading setup script..."
  safe_download \
    "https://github.com/${GITHUB_REPO}/releases/latest/download/setup.sh" \
    "${INSTALL_DIR}/setup.sh"
  chmod +x "${INSTALL_DIR}/setup.sh"

  ln -sf "${INSTALL_DIR}/virlink"  /usr/local/bin/virlink      2>/dev/null || true
  ln -sf "${INSTALL_DIR}/setup.sh" /usr/local/bin/virlink-setup 2>/dev/null || true

  local ver
  ver=$("${INSTALL_DIR}/virlink" --version 2>/dev/null || echo "?")
  ok "${BOLD}${ver}${NC} installed to ${INSTALL_DIR}"
  ok "Commands: ${W}virlink-setup${NC}  ${W}virlink${NC}"
  echo
  exec "${INSTALL_DIR}/setup.sh"
}

# ══════════════════════════════════════════════════════════════════════════════
# Core update / remove
# ══════════════════════════════════════════════════════════════════════════════
check_update() {
  local current latest raw
  set +e
  current=$("$VIRLINK_BIN" --version 2>/dev/null \
    | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")
  [[ -n "$current" && "$current" != v* ]] && current="v${current}"

  raw=$(curl -fsSL --connect-timeout 5 --max-time 8 \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" 2>/dev/null)
  latest=$(echo "$raw" \
    | grep '"tag_name"' | head -1 \
    | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
  set -e

  LATEST_TAG="${latest:-}"
  if [[ -n "$latest" && -n "$current" && "${latest#v}" != "${current#v}" ]]; then
    UPDATE_AVAILABLE=1
  else
    UPDATE_AVAILABLE=0
  fi
}

do_update_core() {
  require_root
  [[ -z "$LATEST_TAG" ]] && { info "Checking latest release..."; check_update; }
  if (( ! UPDATE_AVAILABLE )); then
    ok "Core is already up to date."
    blank; press_enter; return
  fi
  info "Downloading virlink ${LATEST_TAG}..."
  safe_download "https://github.com/${GITHUB_REPO}/releases/latest/download/virlink" \
    "${VIRLINK_BIN}.new"
  chmod +x "${VIRLINK_BIN}.new"
  mv "${VIRLINK_BIN}.new" "$VIRLINK_BIN"
  ok "Core updated to ${LATEST_TAG}."
  blank; press_enter
}

do_update_script() {
  require_root
  info "Downloading latest setup script..."
  safe_download "https://github.com/${GITHUB_REPO}/releases/latest/download/setup.sh" \
    "${INSTALL_DIR}/setup.sh.new"
  chmod +x "${INSTALL_DIR}/setup.sh.new"
  mv "${INSTALL_DIR}/setup.sh.new" "${INSTALL_DIR}/setup.sh"
  ok "Setup script updated — restarting..."
  blank
  exec "${INSTALL_DIR}/setup.sh"
}

do_update_all() {
  require_root
  [[ -z "$LATEST_TAG" ]] && { info "Checking latest release..."; check_update; }
  if (( ! UPDATE_AVAILABLE )); then
    ok "Already up to date."
    exit 0
  fi
  info "Downloading virlink ${LATEST_TAG}..."
  safe_download "https://github.com/${GITHUB_REPO}/releases/latest/download/virlink" \
    "${VIRLINK_BIN}.new"
  chmod +x "${VIRLINK_BIN}.new"
  mv "${VIRLINK_BIN}.new" "$VIRLINK_BIN"
  ok "Core updated to ${LATEST_TAG}."
  do_update_script
}

do_remove_core() {
  require_root
  blank
  warn "This removes the virlink binary, all tunnel services, configs, and logs."
  if ! confirm "Remove Virtlink Core completely"; then
    return
  fi

  local unit name
  for unit in /etc/systemd/system/virlink-*.service; do
    [[ -f "$unit" ]] || continue
    name=$(basename "$unit" .service)
    info "Stopping ${name}..."
    systemctl stop    "$name" 2>/dev/null || true
    systemctl disable "$name" 2>/dev/null || true
    rm -f "$unit"
  done
  systemctl daemon-reload 2>/dev/null || true

  info "Removing install directory ${INSTALL_DIR}..."
  rm -rf "$INSTALL_DIR"
  info "Removing logs ${LOGS_DIR}..."
  rm -rf "$LOGS_DIR"
  rm -f /usr/local/bin/virlink /usr/local/bin/virlink-setup 2>/dev/null || true

  ok "Virtlink Core removed."
  blank
  press_enter
  exit 0
}

# ══════════════════════════════════════════════════════════════════════════════
# Prerequisites
# ══════════════════════════════════════════════════════════════════════════════
require_root() { [[ $EUID -eq 0 ]] || die "Requires root — run: sudo virlink-setup"; }
require_bin()  { [[ -x "$VIRLINK_BIN" ]] || die "Binary not found: $VIRLINK_BIN"; }
ensure_dirs()  { mkdir -p "$CONFIGS_DIR" "$LOGS_DIR"; }

# ══════════════════════════════════════════════════════════════════════════════
# Systemd service helpers
# ══════════════════════════════════════════════════════════════════════════════
svc_name()       { echo "virlink-${1}"; }
svc_unit()       { echo "/etc/systemd/system/virlink-${1}.service"; }
svc_log()        { echo "${LOGS_DIR}/${1}.log"; }

tunnel_is_running() {
  systemctl is-active "$(svc_name "$1")" &>/dev/null
}

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

  info "Purging journal for ${svc}..."
  if journalctl --unit="$svc" --disk-usage &>/dev/null; then
    journalctl --rotate 2>/dev/null || true
    journalctl --vacuum-time=1s 2>/dev/null || true
  fi

  info "Removing log file ${log}..."
  rm -f "$log"

  info "Removing config ${cfg}..."
  rm -f "$cfg"

  ok "Tunnel '${name}' completely removed."
  blank
}

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

tunnel_status() {
  local name="$1"
  local cfg="${CONFIGS_DIR}/${name}.toml"
  local svc; svc="$(svc_name "$name")"
  local log; log="$(svc_log "$name")"

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
  sep_thin

  local running=0
  if tunnel_is_running "$name"; then
    running=1
    echo -e "  ${G}${BOLD}● RUNNING${NC}  ${DIM}(${svc})${NC}"
  else
    echo -e "  ${R}● STOPPED${NC}  ${DIM}(${svc})${NC}"
  fi

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

  blank
  echo -e "  ${DIM}── systemd ──────────────────────────────────────${NC}"
  systemctl status "$svc" --no-pager -l --lines=0 2>/dev/null | \
    grep -E '(Loaded|Active|Main PID|Tasks|Memory|CPU)' | sed 's/^/  /' || true

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

# ══════════════════════════════════════════════════════════════════════════════
# Tunnel listing & selection
# ══════════════════════════════════════════════════════════════════════════════
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
  sep_thin
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

list_tunnels() {
  local cfgs=()
  mapfile -t cfgs < <(find "$CONFIGS_DIR" -maxdepth 1 -name "*.toml" 2>/dev/null | sort)
  if [[ ${#cfgs[@]} -eq 0 ]]; then
    warn "No tunnels configured yet."
    return 1
  fi
  blank
  printf "  ${BOLD}%-4s %-26s %-18s %-10s %s${NC}\n" "#" "NAME" "TYPE" "STATUS" "REMOTE"
  sep_thin
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

# ══════════════════════════════════════════════════════════════════════════════
# Tunnel type definitions & dispatch
# ══════════════════════════════════════════════════════════════════════════════
_kernel_tunnel_labels() {
  cat << 'EOF'
gre-fou        — GRE in UDP (FOU)                  fast, no encryption
ipip-fou       — IPIP in UDP (FOU)                 minimal overhead
bonded-gre-fou — Dual GRE-FOU ECMP                 2× bandwidth
l2tpv3         — L2TPv3 over UDP                   Layer-2 tunnel
gre-wg         — GRE inside WireGuard              encrypted
gre-fou-ipsec  — GRE-FOU + IPsec ESP               encrypted + FOU
gre            — Kernel GRE (proto 47)             no UDP wrapper
EOF
}

_userspace_tunnel_labels() {
  cat << 'EOF'
icmp           — ICMP Echo tunnel (proto 1)        DPI bypass
udp            — User-space UDP tunnel             plain UDP
bip            — BIP tunnel (proto 58)             DPI bypass
tcp            — User-space TCP tunnel             auto-reconnect
udp-obfs       — Obfuscated UDP (AES-256-GCM)      DPI bypass (Iran)
EOF
}

pick_tunnel_type() {
  local category="$1"
  local labels=() ttype key

  if [[ "$category" == "kernel" ]]; then
    mapfile -t labels < <(_kernel_tunnel_labels)
    pick ttype "Kernel tunnel type" "${labels[@]}"
  else
    mapfile -t labels < <(_userspace_tunnel_labels)
    pick ttype "Userspace tunnel type" "${labels[@]}"
  fi

  key="${ttype%%[[:space:]]*}"
  printf '%s\n' "$key"
}

dispatch_tunnel_generator() {
  local key="$1"
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
}

# ══════════════════════════════════════════════════════════════════════════════
# Config helpers
# ══════════════════════════════════════════════════════════════════════════════
collect_base_inputs() {
  local _n _m _l _r _c
  blank
  prompt _n "Tunnel name (e.g. kharej-gre)" ""
  [[ -z "$_n" ]] && die "Name cannot be empty."
  _n="${_n// /-}"
  if [[ -n "${PRESELECTED_MODE:-}" ]]; then
    _m="$PRESELECTED_MODE"
    info "Mode: ${_m}"
  else
    pick _m "Mode" "client" "server"
  fi
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

write_userspace_tuning() {
  local file="$1" proto="$2"
  case "$proto" in
    icmp)
      cat >> "$file" << EOF

[tuning]
enabled      = true
mode         = "fast"
sock_buf_mb  = 64
tun_queues   = 2
batch_size   = 64
poll_ms      = 5
tx_queue_len = 10000

[logging]
level            = "info"
profile          = true
profile_interval = 30
EOF
      ;;
    udp|bip)
      cat >> "$file" << EOF

[tuning]
enabled      = true
mode         = "fast"
sock_buf_mb  = 32
tun_queues   = 1
poll_ms      = 10
tx_queue_len = 10000

[logging]
level            = "info"
profile          = true
profile_interval = 30
EOF
      ;;
    tcp)
      cat >> "$file" << EOF

[tuning]
enabled      = true
mode         = "fast"
sock_buf_mb  = 32
tun_queues   = 1
tcp_streams  = 2
poll_ms      = 10
tx_queue_len = 10000

[logging]
level            = "info"
profile          = true
profile_interval = 30
EOF
      ;;
    *)
      write_tuning "$file"
      return
      ;;
  esac
  cat >> "$file" << EOF

[health]
disabled = false
port     = 6543
EOF
}

write_tuning() {
  local file="$1" multipath="${2:-false}"
  cat >> "$file" << EOF

[tuning]
enabled      = true
mode         = "balanced"
multipath    = ${multipath}
# sock_buf_mb  = 32     # socket buffer MB  (1–128, default 32)
# tun_queues   = 4      # TUN readers       (1–16,  default = CPU count max 4)
# batch_size   = 32     # ICMP sendmmsg     (1–128, default 32)
# tx_queue_len = 10000  # TUN txqueuelen    (100–100000)
# poll_ms      = 10     # idle poll ms      (adaptive backoff up to 50 ms)
# tcp_streams  = 4      # TCP streams       (1–16,  default = tun_queues)
channel_size  = 10_000

[logging]
level            = "info"
profile          = true
profile_interval = 30

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

# ══════════════════════════════════════════════════════════════════════════════
# Config generators
# ══════════════════════════════════════════════════════════════════════════════
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
  sep_thin
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
  write_userspace_tuning "$cfg" "tcp"
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
  write_userspace_tuning "$cfg" "udp"
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
  write_userspace_tuning "$cfg" "icmp"
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
  write_userspace_tuning "$cfg" "bip"
  add_forward_section "$cfg" "$mode"
  LAST_CFG_PATH="$cfg"
}

# ══════════════════════════════════════════════════════════════════════════════
# Menu handlers
# ══════════════════════════════════════════════════════════════════════════════
menu_create_tunnel() {
  show_banner
  echo -e "  ${BOLD}Configure a New Tunnel${NC}"
  sep_thin

  local mode_raw category_raw tunnel_key
  pick mode_raw "Select mode" \
    "client — initiator / outbound side" \
    "server — listener / inbound side"
  PRESELECTED_MODE="${mode_raw%%[[:space:]]*}"

  blank
  pick category_raw "Select tunnel category" \
    "kernel     — Kernel datapath (GRE, FOU, WireGuard, IPsec...)" \
    "userspace  — Userspace transport (ICMP, UDP, TCP, BIP, obfs)"
  local category="${category_raw%%[[:space:]]*}"

  tunnel_key=$(pick_tunnel_type "$category")
  dispatch_tunnel_generator "$tunnel_key"
  PRESELECTED_MODE=""

  blank
  ok "Config saved: ${LAST_CFG_PATH}"
  blank
  echo -e "  ${DIM}Config preview:${NC}"
  sep_thin
  grep -v '^#' "${LAST_CFG_PATH}" | grep -v '^$' | head -28 | sed 's/^/    /'
  blank

  require_root
  ensure_dirs
  local name; name=$(basename "${LAST_CFG_PATH}" .toml)
  info "Installing as systemd service and starting..."
  tunnel_start "$name"

  blank
  press_enter
}

menu_tunnel_management() {
  show_banner
  echo -e "  ${BOLD}Tunnel Management${NC}"
  sep_thin
  ensure_dirs
  if ! pick_tunnel; then
    press_enter
    return
  fi
  local name="$PICKED_TUNNEL"

  blank
  if tunnel_is_running "$name"; then
    echo -e "  ${G}●${NC} ${BOLD}${name}${NC} is ${G}RUNNING${NC}"
  else
    echo -e "  ${R}●${NC} ${BOLD}${name}${NC} is ${R}STOPPED${NC}"
  fi
  blank

  local action
  pick action "Action" \
    "start     — install service + start" \
    "stop      — stop + disable service" \
    "restart   — restart service" \
    "status    — show status, logs, and systemctl" \
    "edit      — open config in editor" \
    "logs      — tail / follow / search logs" \
    "forward   — add port forwarding rule" \
    "keygen    — generate WireGuard keypair" \
    "remove    — delete tunnel + service"
  action="${action%%[[:space:]]*}"

  case "$action" in
    start|stop|restart|status|edit|remove)
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
      ;;
    logs)
      _manage_logs "$name"
      ;;
    forward)
      _manage_forward "$name"
      ;;
    keygen)
      _manage_keygen
      ;;
  esac
  blank
  press_enter
}

menu_check_status() {
  show_banner
  echo -e "  ${BOLD}Check Tunnel Status${NC}"
  sep_thin
  ensure_dirs

  if ! list_tunnels; then
    press_enter
    return
  fi

  if confirm "Show detailed status for a tunnel"; then
    if pick_tunnel; then
      tunnel_status "$PICKED_TUNNEL"
    fi
  fi
  blank
  press_enter
}

menu_update_core() {
  show_banner
  echo -e "  ${BOLD}Update Virtlink Core${NC}"
  sep_thin
  info "Checking GitHub for latest release..."
  check_update
  local cur_ver
  cur_ver=$(core_version)
  blank
  echo -e "  Installed : ${W}${cur_ver}${NC}"
  if [[ -z "$LATEST_TAG" ]]; then
    echo -e "  Latest    : ${R}could not reach GitHub${NC}"
    echo -e "  ${DIM}Check: curl -s https://api.github.com/repos/${GITHUB_REPO}/releases/latest | grep tag_name${NC}"
    blank
    press_enter
    return
  fi
  echo -e "  Latest    : ${W}${LATEST_TAG}${NC}"
  blank
  if (( UPDATE_AVAILABLE )); then
    if confirm "Update core to ${LATEST_TAG}"; then
      do_update_core
      return
    fi
  else
    ok "Core is already up to date."
  fi
  blank
  press_enter
}

menu_update_script() {
  show_banner
  echo -e "  ${BOLD}Update Setup Script${NC}"
  sep_thin
  if confirm "Download latest setup.sh from GitHub releases"; then
    do_update_script
  else
    blank
    press_enter
  fi
}

menu_remove_core() {
  show_banner
  echo -e "  ${BOLD}Remove Virtlink Core${NC}"
  sep_thin
  do_remove_core
}

# Sub-handlers (formerly top-level menu items)
_manage_forward() {
  local name="$1"
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
    require_root
    systemctl restart "$(svc_name "$name")" 2>/dev/null || true
    ok "Restarted."
  fi
}

_manage_logs() {
  local name="$1"
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
  read -r mode _ <<< "$mode"

  blank

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
        sep_thin
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
      sep_thin
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
      sep_thin
      ;;
  esac
}

_manage_keygen() {
  blank
  echo -e "  ${BOLD}Generate WireGuard Keypair${NC}"
  sep_thin
  require_bin
  blank
  "$VIRLINK_BIN" keygen
}

# ══════════════════════════════════════════════════════════════════════════════
# Main loop
# ══════════════════════════════════════════════════════════════════════════════
main() {
  require_bin
  mkdir -p "$CONFIGS_DIR"

  check_update &
  local _bg=$!

  while true; do
    if [[ -n "${_bg:-}" ]]; then
      wait "$_bg" 2>/dev/null || true
      _bg=""
    fi

    show_banner
    echo -e "  ${BOLD}Main Menu${NC}"
    sep_thin
    echo -e "    ${C} 1${NC}  Configure a new tunnel"
    echo -e "    ${C} 2${NC}  Tunnel management"
    echo -e "    ${C} 3${NC}  Check tunnel status"
    if (( UPDATE_AVAILABLE )); then
      echo -e "    ${Y} 4${NC}  ${Y}Update Virtlink Core${NC}  → ${LATEST_TAG}"
    else
      echo -e "    ${C} 4${NC}  Update Virtlink Core"
    fi
    echo -e "    ${C} 5${NC}  Update script"
    echo -e "    ${C} 6${NC}  Remove Virtlink Core"
    echo -e "    ${C} 0${NC}  Exit"
    blank
    tty_out "  ${W}?${NC} Choose [0-6]: "
    read -r choice < /dev/tty
    case "$choice" in
      1) menu_create_tunnel ;;
      2) menu_tunnel_management ;;
      3) menu_check_status ;;
      4) menu_update_core ;;
      5) menu_update_script ;;
      6) menu_remove_core ;;
      0) blank; ok "Goodbye."; blank; exit 0 ;;
      *) warn "Invalid choice." ;;
    esac
  done
}

# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════
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
  update)  require_root; check_update; do_update_all ;;
  menu)    main ;;
  *)       echo "Usage: $0 [menu|start|stop|restart|status|list|update] [name]"; exit 1 ;;
esac
