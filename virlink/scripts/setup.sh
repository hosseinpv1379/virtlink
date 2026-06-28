#!/usr/bin/env bash
# virlink — kernel & userspace tunnel manager  (setup & management)
# Public install: https://github.com/hosseinpv1379/virtlink/releases/latest/download/setup.sh
set -euo pipefail

# ══════════════════════════════════════════════════════════════════════════════
# Constants & paths
# ══════════════════════════════════════════════════════════════════════════════
SCRIPT_VERSION="1.1.0"
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
PICKED_TUNNEL_TYPE=""  # set by pick_tunnel_type (never capture pick UI via $())
PRESELECTED_MODE=""  # set during create flow (client/server chosen upfront)

# Kernel vs userspace tunnel classification
readonly -a KERNEL_TUNNEL_KEYS=(
  gre-fou ipip-fou bonded-gre-fou l2tpv3 gre-fou-ipsec gre
)
readonly -a USERSPACE_TUNNEL_KEYS=(
  icmp udp bip tcp udp-obfs openvpn
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

# First token from a menu label like "gre-fou — description".
label_key() {
  local s="$1"
  s="${s//$'\n'/}"
  s="${s%%[[:space:]]*}"
  echo "$s"
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
  if [[ -n "$ver" && "$ver" != v* ]]; then
    ver="v${ver}"
  fi
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
  if [[ -n "$ip" ]]; then
    echo "$ip"
    return 0
  fi
  ip=$(detect_local_ip)
  echo "${ip:-unknown}"
}

# Sets GEO_LOCATION and GEO_DATACENTER globals (empty when unavailable)
fetch_geo_info() {
  GEO_LOCATION=""
  GEO_DATACENTER=""
  local ip="${1:-}"
  if [[ -z "$ip" || "$ip" == "unknown" ]]; then
    return 0
  fi

  local raw city country isp org status
  raw=$(curl -fsSL --connect-timeout 3 --max-time 3 \
    "http://ip-api.com/json/${ip}?fields=status,city,country,isp,org" 2>/dev/null || echo "")
  if [[ -z "$raw" ]]; then
    return 0
  fi

  status=$(echo "$raw" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)
  if [[ "$status" != "success" ]]; then
    return 0
  fi

  city=$(echo "$raw"    | grep -o '"city":"[^"]*"'    | head -1 | cut -d'"' -f4)
  country=$(echo "$raw" | grep -o '"country":"[^"]*"' | head -1 | cut -d'"' -f4)
  isp=$(echo "$raw"     | grep -o '"isp":"[^"]*"'     | head -1 | cut -d'"' -f4)
  org=$(echo "$raw"     | grep -o '"org":"[^"]*"'     | head -1 | cut -d'"' -f4)

  if [[ -n "$city" || -n "$country" ]]; then
    GEO_LOCATION="${city:-?}, ${country:-?}"
  fi
  if [[ -n "$org" ]]; then
    GEO_DATACENTER="$org"
  elif [[ -n "$isp" ]]; then
    GEO_DATACENTER="$isp"
  fi
  return 0
}

# ══════════════════════════════════════════════════════════════════════════════
# Banner
# ══════════════════════════════════════════════════════════════════════════════
show_banner() {
  clear
  echo -e "${BOLD}${C}"
  echo "▗▄▄▖ ▗▖ ▗▖▗▖  ▗▖▗▙▄▖ ▗▖     ▗▖ ▗▖▗▖ ▗▖"
  echo "▐▌ ▐▌▐▌ ▐▌▐▛ ▐▌▐▌ ▐▌▐▌     ▐▌ ▐▌▐▌ ▐▌"
  echo "▐▛▀▚▖▐▛▀▜▌▐▌ ▐▌▐▌ ▐▌▐▌     ▐▌ ▐▌▐▛▀▜▌"
  echo "▐▙▄▞▘▐▌ ▐▌▐▙▄▞▘▝▚▄▞▘▐▙▄▄▖    ▝▚▄▞▘▐▌ ▐▌"
  echo -e "${NC}"
  echo -e "  ${W}${BOLD}virlink${NC} ${DIM}— ${TAGLINE}${NC}"
  echo

  local core_ver ip geo_loc geo_dc core_state
  core_ver=$(core_version || echo "?")
  ip=$(detect_ip || echo "unknown")
  fetch_geo_info "$ip" || true
  geo_loc="${GEO_LOCATION:-—}"
  geo_dc="${GEO_DATACENTER:-—}"

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
  echo -e "  ${DIM}Location:${NC}         ${geo_loc}"
  echo -e "  ${DIM}Datacenter:${NC}       ${geo_dc}"
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

_is_piped_curl() {
  [[ "$0" == /dev/fd/* ]] || [[ "$0" == /proc/self/fd/* ]]
}

_is_piped_install() {
  _is_piped_curl || [[ ! -f "$VIRLINK_BIN" ]]
}

ensure_deps() {
  local missing=()
  command -v curl  &>/dev/null || missing+=(curl)
  command -v chmod &>/dev/null || missing+=(coreutils)
  if ((${#missing[@]})); then
    die "Missing required tools: ${missing[*]}.  Install them and retry."
  fi
}

_verify_setup_script() {
  local f="$1"
  grep -q 'SCRIPT_VERSION=' "$f" \
    || die "Saved setup script is incomplete (missing SCRIPT_VERSION)"
  grep -qE '^main\(\)' "$f" \
    || die "Saved setup script is incomplete (missing main function)"
}

install_setup_script() {
  local dest="${INSTALL_DIR}/setup.sh"
  info "Saving setup script to ${dest}..."
  safe_download \
    "https://github.com/${GITHUB_REPO}/releases/latest/download/setup.sh" \
    "$dest"
  chmod +x "$dest"
  _verify_setup_script "$dest"
  ln -sf "$dest" /usr/local/bin/virlink-setup 2>/dev/null || true
}

do_install() {
  echo -e "\n${BOLD}${B}  virlink installer${NC}\n"
  [[ $EUID -eq 0 ]] || die "Installer requires root.  Re-run: sudo bash <(curl ...)"
  ensure_deps

  info "Creating ${INSTALL_DIR}..."
  mkdir -p "${INSTALL_DIR}/configs" || die "Cannot create ${INSTALL_DIR}"

  info "Downloading virlink binary..."
  safe_download \
    "https://github.com/${GITHUB_REPO}/releases/latest/download/virlink" \
    "${INSTALL_DIR}/virlink"
  chmod +x "${INSTALL_DIR}/virlink"
  ln -sf "${INSTALL_DIR}/virlink" /usr/local/bin/virlink 2>/dev/null || true

  install_setup_script

  local ver
  ver=$("${INSTALL_DIR}/virlink" --version 2>/dev/null || echo "?")
  ok "${BOLD}${ver}${NC} installed to ${INSTALL_DIR}"
  ok "Setup script saved to ${INSTALL_DIR}/setup.sh"
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
  ensure_deps
  mkdir -p "$INSTALL_DIR"
  info "Downloading latest setup script..."
  safe_download "https://github.com/${GITHUB_REPO}/releases/latest/download/setup.sh" \
    "${INSTALL_DIR}/setup.sh.new"
  chmod +x "${INSTALL_DIR}/setup.sh.new"
  _verify_setup_script "${INSTALL_DIR}/setup.sh.new"
  mv "${INSTALL_DIR}/setup.sh.new" "${INSTALL_DIR}/setup.sh"
  ln -sf "${INSTALL_DIR}/setup.sh" /usr/local/bin/virlink-setup 2>/dev/null || true
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
require_cmd()  { command -v "$1" >/dev/null 2>&1 || die "'$1' not found — install it first"; }
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
openvpn        — OpenVPN core (encrypted link)     UDP/TCP · high throughput
udp-obfs       — Obfuscated UDP (AES-256-GCM)      DPI bypass (Iran)
EOF
}

pick_tunnel_type() {
  local category="$1"
  local labels=() ttype

  PICKED_TUNNEL_TYPE=""
  if [[ "$category" == "kernel" ]]; then
    mapfile -t labels < <(_kernel_tunnel_labels)
    pick ttype "Kernel tunnel type" "${labels[@]}"
  else
    mapfile -t labels < <(_userspace_tunnel_labels)
    pick ttype "Userspace tunnel type" "${labels[@]}"
  fi

  PICKED_TUNNEL_TYPE="$(label_key "$ttype")"
  [[ -n "$PICKED_TUNNEL_TYPE" ]] || die "Could not parse tunnel type."
}

dispatch_tunnel_generator() {
  local key
  key="$(label_key "$1")"
  LAST_CFG_PATH=""
  case "$key" in
    gre-fou)        gen_gre_fou  ;;
    ipip-fou)       gen_ipip_fou ;;
    bonded-gre-fou) gen_bonded   ;;
    l2tpv3)         gen_l2tpv3   ;;
    udp-obfs)       gen_udp_obfs ;;
    gre-fou-ipsec)  gen_ipsec    ;;
    gre)            gen_gre      ;;
    tcp)            gen_tcp      ;;
    openvpn)        gen_openvpn  ;;
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
    openvpn)
      write_openvpn_tuning "$file" "fast"
      return
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

# ── OpenVPN PKI + config helpers ─────────────────────────────────────────────

openvpn_overlay_ips() {
  local cidr="$1" mode="$2"
  local net="${cidr%/*}"
  local base="${net%.*}"
  OPENVPN_CLIENT_IP="${base}.1"
  OPENVPN_SERVER_IP="${base}.2"
}

# MTU / MSS tuned for OpenVPN crypto + transport overhead (UDP ≈ max bandwidth).
openvpn_mtu_for_proto() {
  local proto="$1"
  if [[ "$proto" == "tcp" ]]; then
    OPENVPN_DEFAULT_MTU=1400
    OPENVPN_TUN_MTU=1400
    OPENVPN_MSSFIX=1360
  else
    OPENVPN_DEFAULT_MTU=1472
    OPENVPN_TUN_MTU=1472
    OPENVPN_MSSFIX=1432
  fi
}

# Shared OpenVPN directives — fast (bandwidth), resource (CPU/power), latency.
openvpn_perf_block() {
  local perf="$1" proto="$2" tun_mtu="$3" mssfix="$4"
  cat << EOF
allow-compression no
topology p2p
fast-io
sndbuf 0
rcvbuf 0
tun-mtu ${tun_mtu}
mssfix ${mssfix}
auth none
data-ciphers AES-128-GCM:CHACHA20-POLY1305
data-ciphers-fallback AES-128-GCM
cipher AES-128-GCM
ncp-ciphers AES-128-GCM:CHACHA20-POLY1305
EOF
  case "$perf" in
    resource)
      cat << EOF
# virlink profile: resource — lower CPU wakeups / power
reneg-sec 86400
keepalive 60 180
verb 0
EOF
      ;;
    latency)
      cat << EOF
# virlink profile: latency — minimal delay
reneg-sec 3600
keepalive 10 60
verb 1
EOF
      [[ "$proto" == "tcp" ]] && echo "tcp-nodelay"
      ;;
    fast|*)
      cat << EOF
# virlink profile: fast — max bandwidth (default)
reneg-sec 0
keepalive 20 90
verb 1
EOF
      [[ "$proto" == "tcp" ]] && echo "tcp-nodelay"
      ;;
  esac
}

write_openvpn_tuning() {
  local file="$1" perf="${2:-fast}"
  local mode="fast" txql=10000 hb=20 poll=50
  case "$perf" in
    resource) mode="resource"; txql=5000; hb=60; poll=100 ;;
    latency)  mode="latency";  txql=8000; hb=10; poll=20 ;;
  esac
  cat >> "$file" << EOF

[tuning]
enabled      = true
mode         = "${mode}"
tx_queue_len = ${txql}
poll_ms      = ${poll}

[logging]
level = "info"

[health]
disabled = false
port     = 6543
EOF
}

openvpn_gen_pki() {
  local dir="$1"
  require_cmd openssl
  require_cmd openvpn
  mkdir -p "$dir"
  chmod 700 "$dir"

  if [[ -f "$dir/ca.crt" ]]; then
    ok "PKI already exists in ${dir}"
    openvpn_export_client_bundle "$dir" 2>/dev/null || true
    return 0
  fi

  info "Generating OpenVPN PKI (ECDSA P-256, tls-crypt, no DH file)..."
  openssl ecparam -genkey -name prime256v1 -out "$dir/ca.key" 2>/dev/null
  openssl req -new -x509 -days 3650 -key "$dir/ca.key" -out "$dir/ca.crt" \
    -subj "/CN=vl-ca" 2>/dev/null

  openssl ecparam -genkey -name prime256v1 -out "$dir/server.key" 2>/dev/null
  openssl req -new -key "$dir/server.key" -out "$dir/server.csr" \
    -subj "/CN=vl-srv" 2>/dev/null
  openssl x509 -req -days 3650 -in "$dir/server.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" \
    -CAcreateserial -out "$dir/server.crt" 2>/dev/null

  openssl ecparam -genkey -name prime256v1 -out "$dir/client.key" 2>/dev/null
  openssl req -new -key "$dir/client.key" -out "$dir/client.csr" \
    -subj "/CN=vl-cli" 2>/dev/null
  openssl x509 -req -days 3650 -in "$dir/client.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" \
    -CAcreateserial -out "$dir/client.crt" 2>/dev/null

  if openvpn --genkey tls-crypt "$dir/tc.key" 2>/dev/null; then
    :
  else
    openvpn --genkey secret "$dir/tc.key"
  fi

  rm -f "$dir/server.csr" "$dir/client.csr"
  chmod 600 "$dir"/*.key "$dir/tc.key" 2>/dev/null || true
  chmod 644 "$dir"/*.crt 2>/dev/null || true
  ok "PKI generated (ECDSA, tls-crypt — server/CA private keys stay on server)"
  openvpn_export_client_bundle "$dir"
}

# Client-safe bundle: public CA + client creds + tls-crypt only (no server/ca private keys).
openvpn_export_client_bundle() {
  local pki_dir="$1"
  local export_dir="${pki_dir}/export"
  local tls_key="tc.key"
  local f
  [[ -f "${pki_dir}/tc.key" ]] || tls_key="ta.key"
  mkdir -p "$export_dir"
  chmod 700 "$export_dir"
  for f in ca.crt client.crt client.key "$tls_key"; do
    [[ -f "${pki_dir}/${f}" ]] || return 1
    cp -f "${pki_dir}/${f}" "${export_dir}/${f}"
  done
  chmod 600 "${export_dir}/client.key" "${export_dir}/${tls_key}"
  chmod 644 "${export_dir}/ca.crt" "${export_dir}/client.crt"
  ok "Client export: ${export_dir} (no server or CA private keys)"
}

# Remove server-only material if it ever lands on a client (privacy).
openvpn_strip_server_secrets() {
  local dir="$1"
  local f
  for f in server.key server.crt ca.key dh.pem ta.key; do
    if [[ -f "${dir}/${f}" ]]; then
      warn "Removing ${f} from client (server-only)"
      rm -f "${dir}/${f}"
    fi
  done
}

openvpn_tls_key_directive() {
  local dir="$1" role="$2"
  if [[ -f "${dir}/tc.key" ]]; then
    echo "tls-crypt tc.key"
  elif [[ -f "${dir}/ta.key" ]]; then
    [[ "$role" == "server" ]] && echo "tls-auth ta.key 0" || echo "tls-auth ta.key 1"
  else
    die "Missing tls-crypt key (tc.key) — fetch PKI from server"
  fi
}

openvpn_fetch_pki_from_server() {
  local name="$1" server_host="$2" pki_dir="$3"
  local ssh_user="${4:-root}" ssh_port="${5:-22}"
  local remote_pki="${INSTALL_DIR}/pki/${name}"
  local remote_export="${remote_pki}/export"
  local ssh_base=(ssh -p "$ssh_port" -o BatchMode=yes -o ConnectTimeout=20 -o StrictHostKeyChecking=accept-new)
  local scp_base=(scp -P "$ssh_port" -o BatchMode=yes -o ConnectTimeout=20 -o StrictHostKeyChecking=accept-new)

  require_cmd ssh
  require_cmd scp
  mkdir -p "$pki_dir"
  chmod 700 "$pki_dir"

  blank
  info "Fetching client credentials from ${ssh_user}@${server_host} (SSH, client bundle only)..."
  if ! "${ssh_base[@]}" "${ssh_user}@${server_host}" "test -d '${remote_pki}'"; then
    die "No PKI on server at ${remote_pki} — run OpenVPN setup on the server first"
  fi

  if "${ssh_base[@]}" "${ssh_user}@${server_host}" "test -d '${remote_export}'"; then
    "${scp_base[@]}" -r "${ssh_user}@${server_host}:${remote_export}/." "${pki_dir}/" \
      || die "SCP failed — check SSH keys: ssh ${ssh_user}@${server_host}"
  else
    local f tls_key="tc.key"
    "${ssh_base[@]}" "${ssh_user}@${server_host}" "test -f '${remote_pki}/tc.key'" \
      || tls_key="ta.key"
    for f in ca.crt client.crt client.key "$tls_key"; do
      "${scp_base[@]}" "${ssh_user}@${server_host}:${remote_pki}/${f}" "${pki_dir}/${f}" \
        || die "Failed to fetch ${f} — re-run server setup to refresh export bundle"
    done
  fi

  openvpn_strip_server_secrets "$pki_dir"
  ok "PKI fetched from ${server_host}"
}

openvpn_push_client_bundle() {
  local name="$1" client_host="$2" pki_dir="$3"
  local ssh_user="${4:-root}" ssh_port="${5:-22}"
  local export_dir="${pki_dir}/export"
  local remote_dir="${INSTALL_DIR}/pki/${name}"

  require_cmd ssh
  require_cmd scp
  openvpn_export_client_bundle "$pki_dir" || die "Export bundle missing — regenerate PKI on server"

  blank
  info "Pushing client credentials to ${ssh_user}@${client_host} (export bundle only)..."
  ssh -p "$ssh_port" -o BatchMode=yes -o ConnectTimeout=20 -o StrictHostKeyChecking=accept-new \
    "${ssh_user}@${client_host}" "mkdir -p '${remote_dir}' && chmod 700 '${remote_dir}'" \
    || die "SSH to client failed — check keys: ssh ${ssh_user}@${client_host}"

  scp -P "$ssh_port" -o BatchMode=yes -o ConnectTimeout=20 -o StrictHostKeyChecking=accept-new \
    -r "${export_dir}/." "${ssh_user}@${client_host}:${remote_dir}/" \
    || die "SCP to client failed"

  ok "Client credentials pushed to ${client_host}:${remote_dir}"
  info "On client: run setup again (same tunnel name) or start the tunnel"
}

openvpn_prompt_ssh() {
  local _u _p
  prompt _u "SSH user" "root"
  prompt _p "SSH port" "22"
  OPENVPN_SSH_USER="$_u"
  OPENVPN_SSH_PORT="$_p"
}

openvpn_write_crypto_block() {
  local dir="$1" role="$2"
  local tls_line
  tls_line="$(openvpn_tls_key_directive "$dir" "$role")"
  if [[ -f "${dir}/tc.key" ]]; then
    cat << EOF
dh none
ecdh-curve prime256v1
${tls_line}
tls-version-min 1.2
EOF
  elif [[ -f "${dir}/dh.pem" ]]; then
    cat << EOF
dh dh.pem
${tls_line}
tls-version-min 1.2
EOF
  else
    die "Incomplete PKI in ${dir} — missing tc.key or dh.pem"
  fi
}

openvpn_write_server_conf() {
  local dir="$1" port="$2" proto="$3" client_ip="$4" server_ip="$5" mtu="$6" dev="$7" perf="$8"
  local tun_mtu="$9" mssfix="${10}"
  cat > "${dir}/server.conf" << EOF
# virlink OpenVPN — server (site-to-site, ${perf} profile, ${proto})
port ${port}
proto ${proto}
dev ${dev}
dev-type tun
user nobody
group nogroup
persist-key
persist-tun
ca ca.crt
cert server.crt
key server.key
EOF
  openvpn_write_crypto_block "$dir" server >> "${dir}/server.conf"
  cat >> "${dir}/server.conf" << EOF
mode server
tls-server
ifconfig ${server_ip} ${client_ip}
EOF
  openvpn_perf_block "$perf" "$proto" "$tun_mtu" "$mssfix" >> "${dir}/server.conf"
  if [[ "$proto" == "udp" ]]; then
    echo "explicit-exit-notify 1" >> "${dir}/server.conf"
  fi
}

openvpn_write_client_conf() {
  local dir="$1" port="$2" proto="$3" remote_ip="$4" client_ip="$5" server_ip="$6" mtu="$7" dev="$8" perf="$9"
  local tun_mtu="${10}" mssfix="${11}"
  cat > "${dir}/client.conf" << EOF
# virlink OpenVPN — client (site-to-site, ${perf} profile, ${proto})
client
dev ${dev}
dev-type tun
proto ${proto}
remote ${remote_ip} ${port}
nobind
persist-key
persist-tun
ca ca.crt
cert client.crt
key client.key
EOF
  openvpn_write_crypto_block "$dir" client >> "${dir}/client.conf"
  cat >> "${dir}/client.conf" << EOF
remote-cert-tls server
ifconfig ${client_ip} ${server_ip}
EOF
  openvpn_perf_block "$perf" "$proto" "$tun_mtu" "$mssfix" >> "${dir}/client.conf"
}

openvpn_require_client_pki() {
  local dir="$1"
  local f
  for f in ca.crt client.crt client.key; do
    [[ -f "${dir}/${f}" ]] || die "Missing ${dir}/${f} — fetch PKI from server"
  done
  [[ -f "${dir}/tc.key" || -f "${dir}/ta.key" ]] \
    || die "Missing tls-crypt key (tc.key) — fetch PKI from server"
  openvpn_strip_server_secrets "$dir"
}

gen_openvpn() {
  local name mode local_ip remote_ip cidr port proto mtu dev pki_dir ovpn_conf cfg perf_raw perf
  local client_ip server_ip tun_mtu mssfix default_mtu hb
  collect_base_inputs name mode local_ip remote_ip cidr
  blank
  info "Transport: UDP = max bandwidth · TCP = firewall-friendly (slower)"
  pick proto "OpenVPN transport" \
    "udp — max bandwidth (recommended)" \
    "tcp — works through strict firewalls"
  proto="$(label_key "$proto")"
  openvpn_mtu_for_proto "$proto"
  default_mtu="$OPENVPN_DEFAULT_MTU"
  tun_mtu="$OPENVPN_TUN_MTU"
  mssfix="$OPENVPN_MSSFIX"
  prompt port "OpenVPN port" "1194"
  prompt mtu "TUN MTU (overlay)" "$default_mtu"
  pick perf_raw "Performance profile" \
    "fast — max bandwidth (recommended)" \
    "resource — lower CPU / power use" \
    "latency — minimal delay"
  perf="$(label_key "$perf_raw")"
  dev="ovpn-tun0"

  require_cmd openvpn
  pki_dir="${INSTALL_DIR}/pki/${name}"
  mkdir -p "$pki_dir"

  if [[ "$mode" == "server" ]]; then
    openvpn_gen_pki "$pki_dir"
  else
    if [[ ! -f "${pki_dir}/ca.crt" ]]; then
      blank
      warn "Client PKI not found locally."
      info "Privacy: only client certs + tls-crypt are fetched (never server/CA private keys)."
      openvpn_prompt_ssh
      openvpn_fetch_pki_from_server "$name" "$remote_ip" "$pki_dir" \
        "$OPENVPN_SSH_USER" "$OPENVPN_SSH_PORT"
    fi
    openvpn_require_client_pki "$pki_dir"
  fi

  openvpn_overlay_ips "$cidr" "$mode"
  client_ip="$OPENVPN_CLIENT_IP"
  server_ip="$OPENVPN_SERVER_IP"

  case "$perf" in
    resource) hb=60 ;;
    latency)  hb=10 ;;
    *)        hb=20 ;;
  esac

  if [[ "$mode" == "server" ]]; then
    ovpn_conf="${pki_dir}/server.conf"
    openvpn_write_server_conf "$pki_dir" "$port" "$proto" "$client_ip" "$server_ip" "$mtu" "$dev" "$perf" "$tun_mtu" "$mssfix"
    ok "Wrote ${ovpn_conf} (${perf}, ${proto})"
    blank
    info "Privacy: CA/server private keys remain on this host only."
    info "Client bundle: ${pki_dir}/export/"
    if confirm "Push client credentials to peer (${remote_ip}) via SSH?"; then
      openvpn_prompt_ssh
      openvpn_push_client_bundle "$name" "$remote_ip" "$pki_dir" \
        "$OPENVPN_SSH_USER" "$OPENVPN_SSH_PORT"
    else
      info "On client: re-run setup — PKI auto-fetches from this server via SSH."
    fi
  else
    ovpn_conf="${pki_dir}/client.conf"
    openvpn_write_client_conf "$pki_dir" "$port" "$proto" "$remote_ip" "$client_ip" "$server_ip" "$mtu" "$dev" "$perf" "$tun_mtu" "$mssfix"
    ok "Wrote ${ovpn_conf} (${perf}, ${proto})"
  fi

  cfg="${CONFIGS_DIR}/${name}.toml"
  cat > "$cfg" << EOF
# virlink — ${name}  (OpenVPN site-to-site · ${perf} · ${proto})
[tunnel]
type      = "openvpn"
mode      = "${mode}"
local_ip  = "${local_ip}"
remote_ip = "${remote_ip}"
cidr      = "${cidr}"
mtu       = ${mtu}
name      = "${name}"

[transport]
port               = ${port}
proto              = "${proto}"
heartbeat_interval = ${hb}

[openvpn]
config = "${ovpn_conf}"
dev    = "${dev}"

[security]
encryption = true
EOF
  write_openvpn_tuning "$cfg" "$perf"
  add_forward_section "$cfg" "$mode"
  LAST_CFG_PATH="$cfg"
  blank
  warn "Firewall: allow ${proto}/${port} between ${local_ip} and ${remote_ip}"
  if [[ "$mode" == "server" ]]; then
    info "Client overlay IP: ${client_ip}  ·  Server overlay IP: ${server_ip}"
  fi
  info "OpenVPN: tun-mtu ${tun_mtu}  mssfix ${mssfix}  profile ${perf}"
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

  local mode_raw category_raw
  pick mode_raw "Select mode" \
    "client — initiator / outbound side" \
    "server — listener / inbound side"
  PRESELECTED_MODE="$(label_key "$mode_raw")"

  blank
  pick category_raw "Select tunnel category" \
    "kernel     — Kernel datapath (GRE, FOU, IPsec, L2TP...)" \
    "userspace  — Userspace transport (ICMP, UDP, TCP, BIP, obfs)"
  local category
  category="$(label_key "$category_raw")"

  pick_tunnel_type "$category"
  dispatch_tunnel_generator "$PICKED_TUNNEL_TYPE"
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
    "remove    — delete tunnel + service"
  action="$(label_key "$action")"

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

# ══════════════════════════════════════════════════════════════════════════════
# Main loop
# ══════════════════════════════════════════════════════════════════════════════
main() {
  mkdir -p "$CONFIGS_DIR" 2>/dev/null || true

  if [[ ! -t 0 ]] || [[ ! -e /dev/tty ]] || [[ ! -r /dev/tty ]]; then
    show_banner
    err "Interactive menu requires a TTY."
    info "Run directly on the server: ${W}sudo virlink-setup${NC}  or  ${W}sudo bash setup.sh menu${NC}"
    exit 1
  fi

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
