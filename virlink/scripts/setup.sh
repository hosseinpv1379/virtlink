#!/usr/bin/env bash
# virlink — kernel & userspace tunnel manager  (setup & management)
# Public install: https://github.com/hosseinpv1379/virtlink/releases/latest/download/setup.sh
set -euo pipefail

# ══════════════════════════════════════════════════════════════════════════════
# Constants & paths
# ══════════════════════════════════════════════════════════════════════════════
SCRIPT_VERSION="1.4.0"
GITHUB_REPO="hosseinpv1379/virtlink"
TELEGRAM_CHANNEL="@Gozar_XRay"
TAGLINE="High-performance kernel & userspace tunneling"

OPENVPN_BUNDLE_PORT="${OPENVPN_BUNDLE_PORT:-8765}"
OPENVPN_BUNDLE_TTL="${OPENVPN_BUNDLE_TTL:-1800}"

INSTALL_DIR="/opt/virlink"
VIRLINK_BIN="${INSTALL_DIR}/virlink"
CONFIGS_DIR="${INSTALL_DIR}/configs"
LOGS_DIR="/var/log/virlink"
MANUAL_CLIENT_CONF_DIR="/root/manual-client-conf"

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
  icmp udp bip tcp udp-obfs openvpn hysteria2 wireguard
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
  blank
  info "Ensuring OpenVPN core (openvpn + openssl)..."
  ensure_openvpn_deps
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

_install_latest_setup_script() {
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
  local sv
  sv=$(grep '^SCRIPT_VERSION=' "${INSTALL_DIR}/setup.sh" | head -1 | sed 's/.*"\([^"]*\)".*/\1/')
  ok "Setup script updated (v${sv})."
}

do_update_core() {
  require_root
  [[ -z "$LATEST_TAG" ]] && { info "Checking latest release..."; check_update; }
  if (( UPDATE_AVAILABLE )); then
    info "Downloading virlink ${LATEST_TAG}..."
    safe_download "https://github.com/${GITHUB_REPO}/releases/latest/download/virlink" \
      "${VIRLINK_BIN}.new"
    chmod +x "${VIRLINK_BIN}.new"
    mv "${VIRLINK_BIN}.new" "$VIRLINK_BIN"
    ok "Core updated to ${LATEST_TAG}."
  else
    ok "Core is already up to date."
  fi
  _install_latest_setup_script
  ensure_openvpn_deps
  blank; press_enter
}

do_update_script() {
  _install_latest_setup_script
  ensure_openvpn_deps
  blank
  exec "${INSTALL_DIR}/setup.sh"
}

do_update_all() {
  require_root
  [[ -z "$LATEST_TAG" ]] && { info "Checking latest release..."; check_update; }
  if (( UPDATE_AVAILABLE )); then
    info "Downloading virlink ${LATEST_TAG}..."
    safe_download "https://github.com/${GITHUB_REPO}/releases/latest/download/virlink" \
      "${VIRLINK_BIN}.new"
    chmod +x "${VIRLINK_BIN}.new"
    mv "${VIRLINK_BIN}.new" "$VIRLINK_BIN"
    ok "Core updated to ${LATEST_TAG}."
  else
    ok "Core is already up to date."
  fi
  _install_latest_setup_script
  ensure_openvpn_deps
  blank
  exec "${INSTALL_DIR}/setup.sh"
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

_detect_pkg_mgr() {
  if command -v apt-get &>/dev/null; then echo apt
  elif command -v dnf &>/dev/null; then echo dnf
  elif command -v yum &>/dev/null; then echo yum
  elif command -v apk &>/dev/null; then echo apk
  elif command -v zypper &>/dev/null; then echo zypper
  else echo ""
  fi
}

_cmd_pkg_name() {
  case "$1" in
    openvpn) echo openvpn ;;
    openssl) echo openssl ;;
    curl)    echo curl ;;
    tar)     echo tar ;;
    ssh|scp)
      case "$(_detect_pkg_mgr)" in
        dnf|yum) echo openssh-clients ;;
        *)       echo openssh-client ;;
      esac
      ;;
    *) echo "$1" ;;
  esac
}

_pkg_install() {
  local -a pkgs=("$@")
  local mgr seen=() p
  mgr="$(_detect_pkg_mgr)"
  [[ -n "$mgr" ]] || die "No supported package manager — install manually: ${pkgs[*]}"

  for p in "${pkgs[@]}"; do
    [[ " ${seen[*]} " == *" $p "* ]] || seen+=("$p")
  done

  if [[ " ${seen[*]} " == *" openvpn "* ]]; then
    case "$mgr" in
      dnf|yum)
        if ! rpm -q epel-release &>/dev/null 2>&1; then
          info "Installing EPEL (required for openvpn on RHEL/CentOS)..."
          "$mgr" install -y epel-release 2>/dev/null || true
        fi
        ;;
    esac
  fi

  info "Installing: ${seen[*]} (${mgr})..."
  case "$mgr" in
    apt)
      DEBIAN_FRONTEND=noninteractive apt-get update -qq \
        || die "apt-get update failed"
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${seen[@]}" \
        || die "apt-get install failed for: ${seen[*]}"
      ;;
    dnf)
      dnf install -y "${seen[@]}" || die "dnf install failed for: ${seen[*]}"
      ;;
    yum)
      yum install -y "${seen[@]}" || die "yum install failed for: ${seen[*]}"
      ;;
    apk)
      apk add --no-cache "${seen[@]}" || die "apk add failed for: ${seen[*]}"
      ;;
    zypper)
      zypper --non-interactive install -y "${seen[@]}" \
        || die "zypper install failed for: ${seen[*]}"
      ;;
  esac
  ok "Packages installed: ${seen[*]}"
}

# Install missing command via system package manager (requires root).
ensure_cmd() {
  local cmd="$1"
  command -v "$cmd" &>/dev/null && return 0
  require_root
  warn "'${cmd}' not found — installing dependency..."
  _pkg_install "$(_cmd_pkg_name "$cmd")"
  command -v "$cmd" &>/dev/null \
    || die "'${cmd}' still missing after package install"
  ok "${cmd} ready"
}
require_cmd() { ensure_cmd "$@"; }

ensure_openvpn_deps() {
  local -a need=() c
  for c in openssl openvpn; do
    command -v "$c" &>/dev/null || need+=("$(_cmd_pkg_name "$c")")
  done
  ((${#need[@]})) || { ok "OpenVPN core ready (openvpn + openssl)"; return 0; }
  require_root
  warn "OpenVPN core missing — installing openvpn + openssl..."
  _pkg_install "${need[@]}"
  for c in openssl openvpn; do
    command -v "$c" &>/dev/null || die "'${c}' still missing after install"
  done
  ok "OpenVPN core installed"
}

openvpn_version_at_least() {
  local major="${1:-2}" minor="${2:-6}"
  local v maj min
  v="$(openvpn --version 2>/dev/null | head -1 || true)"
  [[ -n "$v" ]] || return 1
  maj="$(sed -n 's/OpenVPN \([0-9]*\)\.\([0-9]*\).*/\1/p' <<< "$v")"
  min="$(sed -n 's/OpenVPN \([0-9]*\)\.\([0-9]*\).*/\2/p' <<< "$v")"
  [[ -n "$maj" && -n "$min" ]] || return 1
  (( maj > major || (maj == major && min >= minor) ))
}

openvpn_dco_module_present() {
  local m
  for m in ovpn_dco_v2 ovpn_dco ovpn; do
    [[ -d "/sys/module/${m}" ]] && return 0
    modprobe "$m" 2>/dev/null || true
    [[ -d "/sys/module/${m}" ]] && return 0
  done
  return 1
}

openvpn_binary_supports_dco() {
  command -v openvpn &>/dev/null || return 1
  openvpn --help 2>&1 | grep -q 'enable-dco'
}

ensure_openvpn_dco() {
  openvpn_binary_supports_dco || {
    warn "openvpn binary has no DCO (enable-dco unknown) — need openvpn-dco-dkms or rebuild with DCO"
    return 1
  }
  openvpn_dco_module_present && { ok "OpenVPN DCO ready (binary + kernel module)"; return 0; }
  require_root
  warn "OpenVPN DCO module not loaded — trying package install..."
  for pkg in openvpn-dco-dkms kmod-ovpn-dco-v2; do
    _pkg_install "$pkg" 2>/dev/null && break
  done
  openvpn_dco_module_present || {
    warn "DCO unavailable — OpenVPN stays single-thread user-space (~1 core per flow)"
    return 1
  }
  ok "OpenVPN DCO module loaded"
}

_wireguard_pkg_name() {
  case "$(_detect_pkg_mgr)" in
    dnf|yum|zypper) echo wireguard-tools ;;
    pacman)         echo wireguard-tools ;;
    apk)            echo wireguard-tools-wg ;;
    *)              echo wireguard-tools ;;
  esac
}

ensure_wireguard_deps() {
  local -a need=() c pkg
  for c in wg; do
    command -v "$c" &>/dev/null || need+=("$(_wireguard_pkg_name)")
  done
  ((${#need[@]})) || { ok "WireGuard ready (wg)"; return 0; }
  require_root
  warn "WireGuard tools missing — installing wireguard-tools..."
  _pkg_install "${need[@]}"
  for c in wg; do
    command -v "$c" &>/dev/null || die "'${c}' still missing after install"
  done
  ok "WireGuard tools installed"
}

ensure_wireguard_module() {
  modprobe wireguard 2>/dev/null || true
  [[ -d /sys/module/wireguard ]] && return 0
  require_root
  warn "wireguard kernel module not loaded — trying kmod package..."
  for pkg in wireguard-dkms kmod-wireguard; do
    _pkg_install "$pkg" 2>/dev/null && break
  done
  modprobe wireguard 2>/dev/null || true
  [[ -d /sys/module/wireguard ]] || warn "wireguard module missing — run: modprobe wireguard"
}

ensure_hysteria2_deps() {
  if command -v hysteria &>/dev/null; then
    ok "Hysteria2 ready ($(hysteria version 2>/dev/null | head -1 || echo hysteria))"
    return 0
  fi
  require_root
  ensure_cmd curl
  local arch="" os="linux" ver url dest="/usr/local/bin/hysteria"
  case "$(uname -m)" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) die "Unsupported CPU for Hysteria2: $(uname -m)" ;;
  esac
  ver=$(curl -fsSL --connect-timeout 8 --max-time 15 \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/apernet/hysteria/releases/latest" 2>/dev/null \
    | grep '"tag_name"' | head -1 | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
  [[ -n "$ver" ]] || die "Cannot fetch Hysteria2 release — check network"
  url="https://github.com/apernet/hysteria/releases/download/${ver}/hysteria-${os}-${arch}"
  info "Downloading Hysteria2 ${ver}..."
  safe_download "$url" "${dest}.new"
  chmod +x "${dest}.new"
  mv "${dest}.new" "$dest"
  command -v hysteria &>/dev/null || die "Hysteria2 install failed"
  ok "Hysteria2 installed (${ver})"
}

ensure_ssh_deps() {
  local -a need=() c
  for c in ssh scp; do
    command -v "$c" &>/dev/null || need+=("$(_cmd_pkg_name "$c")")
  done
  ((${#need[@]})) || return 0
  require_root
  _pkg_install "$(_cmd_pkg_name ssh)"
  for c in ssh scp; do
    command -v "$c" &>/dev/null || die "'${c}' still missing — install openssh-client"
  done
}

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

_cfg_tunnel_type() {
  grep -E '^\s*type\s*=' "$1" 2>/dev/null | head -1 | awk -F'"' '{print $2}'
}

_cfg_tunnel_mode() {
  grep -E '^\s*mode\s*=' "$1" 2>/dev/null | head -1 | awk -F'"' '{print $2}'
}

_cfg_transport_port() {
  awk -F= '/^\[transport\]/{t=1; next} /^\[/{t=0} t && /^[[:space:]]*port[[:space:]]*=/{
    gsub(/[[:space:]]/,"",$2); print $2; exit
  }' "$1" 2>/dev/null
}

tunnel_start() {
  local name="$1"
  local cfg="${CONFIGS_DIR}/${name}.toml"
  [[ -f "$cfg" ]] || die "Config not found: $cfg"
  if [[ "$(_cfg_tunnel_type "$cfg")" == "openvpn" ]]; then
    ensure_openvpn_deps
    ensure_openvpn_dco || true
  fi
  if [[ "$(_cfg_tunnel_type "$cfg")" == "hysteria2" ]]; then
    ensure_hysteria2_deps
  fi
  if [[ "$(_cfg_tunnel_type "$cfg")" == "wireguard" ]]; then
    ensure_wireguard_deps
    ensure_wireguard_module
    if [[ "$(_cfg_tunnel_mode "$cfg")" == "server" ]]; then
      wireguard_allow_firewall_port "$(_cfg_transport_port "$cfg")"
    fi
  fi
  if [[ "$(_cfg_tunnel_type "$cfg")" == "ikev2" ]]; then
    ensure_ikev2_deps
    if [[ "$(_cfg_tunnel_mode "$cfg")" == "server" ]]; then
      ikev2_allow_firewall
    fi
  fi
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
hysteria2      — Hysteria2 QUIC tunnel             fast · censorship-resistant
wireguard      — WireGuard (kernel crypto)         UDP · fast site-to-site
ikev2          — IKEv2 / strongSwan IPsec          UDP 500/4500 · kernel multi-core
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
    hysteria2)     gen_hysteria2 ;;
    wireguard)     gen_wireguard ;;
    ikev2)         gen_ikev2 ;;
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
    hysteria2)
      cat >> "$file" << EOF

[tuning]
enabled      = true
mode         = "fast"
poll_ms      = 50
tx_queue_len = 10000

[logging]
level            = "info"
profile          = true
profile_interval = 30

[health]
disabled = true
EOF
      return
      ;;
    wireguard)
      write_openvpn_tuning "$file" "fast"
      return
      ;;
    ikev2)
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
  virlink_server_write_manual_client "$name" "$mode" "$remote_ip" "$local_ip" "$cfg" "gre-fou" "$port"
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
  virlink_server_write_manual_client "$name" "$mode" "$remote_ip" "$local_ip" "$cfg" "ipip-fou" "$port"
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
  virlink_server_write_manual_client "$name" "$mode" "$remote_ip" "$local_ip" "$cfg" "bonded-gre-fou" "$port1"
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
  virlink_server_write_manual_client "$name" "$mode" "$remote_ip" "$local_ip" "$cfg" "l2tpv3" "$port"
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
  virlink_server_write_manual_client "$name" "$mode" "$remote_ip" "$local_ip" "$cfg" "udp-obfs" "$port"
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
  virlink_server_write_manual_client "$name" "$mode" "$remote_ip" "$local_ip" "$cfg" "gre-fou-ipsec" "$port"
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
  virlink_server_write_manual_client "$name" "$mode" "$remote_ip" "$local_ip" "$cfg" "gre" "0"
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
float
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
      [[ "$proto" == "tcp" ]] && echo "tcp-nodelay" || true
      ;;
    fast|*)
      cat << EOF
# virlink profile: fast — max bandwidth (default)
reneg-sec 0
keepalive 20 90
verb 1
EOF
      [[ "$proto" == "tcp" ]] && echo "tcp-nodelay" || true
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

openvpn_cert_needs_openssl3_upgrade() {
  local crt="$1"
  openssl x509 -in "$crt" -noout -ext extendedKeyUsage &>/dev/null || return 0
  return 1
}

openvpn_openssl_extfile() {
  local dir="$1"
  local f="${dir}/openssl-ext.cnf"
  cat > "$f" << 'EOF'
[ v3_server ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash

[ v3_client ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
EOF
  chmod 600 "$f"
}

# CA: OpenSSL 3 accepts -addext on req; 1.1.x needs a full -config with [req] x509_extensions.
openvpn_create_ca_cert() {
  local dir="$1"
  if openssl req -new -x509 -days 3650 -key "$dir/ca.key" -out "$dir/ca.crt" \
      -subj "/CN=vl-ca" \
      -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null; then
    return 0
  fi
  cat > "${dir}/openssl-ca.cnf" << 'EOF'
[ req ]
default_bits = 256
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_ca

[ dn ]
CN = vl-ca

[ v3_ca ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF
  chmod 600 "${dir}/openssl-ca.cnf"
  openssl req -new -x509 -days 3650 -key "$dir/ca.key" -out "$dir/ca.crt" \
    -config "${dir}/openssl-ca.cnf" \
    || die "OpenSSL: cannot create CA certificate"
}

openvpn_sign_server_cert() {
  local dir="$1"
  local ext="${dir}/openssl-ext.cnf"
  openvpn_openssl_extfile "$dir"
  openssl req -new -key "$dir/server.key" -out "$dir/server.csr" -subj "/CN=vl-srv" \
    || die "OpenSSL: cannot create server CSR"
  openssl x509 -req -days 3650 -in "$dir/server.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" \
    -CAcreateserial -out "$dir/server.crt" \
    -extensions v3_server -extfile "$ext" \
    || die "OpenSSL: cannot sign server certificate"
}

openvpn_sign_client_cert() {
  local dir="$1"
  local ext="${dir}/openssl-ext.cnf"
  openvpn_openssl_extfile "$dir"
  openssl req -new -key "$dir/client.key" -out "$dir/client.csr" -subj "/CN=vl-cli" \
    || die "OpenSSL: cannot create client CSR"
  openssl x509 -req -days 3650 -in "$dir/client.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" \
    -CAcreateserial -out "$dir/client.crt" \
    -extensions v3_client -extfile "$ext" \
    || die "OpenSSL: cannot sign client certificate"
}

openvpn_upgrade_pki_openssl3() {
  local dir="$1"
  [[ -f "$dir/server.key" && -f "$dir/client.key" ]] || return 1
  if ! openvpn_cert_needs_openssl3_upgrade "$dir/server.crt"; then
    return 0
  fi
  info "Upgrading PKI for OpenSSL 3 (adding certificate key usage extensions)..."
  openvpn_sign_server_cert "$dir"
  openvpn_sign_client_cert "$dir"
  rm -f "$dir/server.csr" "$dir/client.csr"
  ok "Certificates re-signed (serverAuth / clientAuth)"
}

openvpn_gen_pki() {
  local dir="$1"
  mkdir -p "$dir"
  chmod 700 "$dir"

  if [[ -f "$dir/ca.crt" ]]; then
    ok "PKI already exists in ${dir}"
    if [[ -f "$dir/tc.key" && -f "$dir/ta.key" ]]; then
      rm -f "$dir/ta.key"
      warn "Removed legacy ta.key (using tls-crypt tc.key only)"
    fi
    openvpn_upgrade_pki_openssl3 "$dir"
    openvpn_export_client_bundle "$dir" 2>/dev/null || true
    return 0
  fi

  info "Generating OpenVPN PKI (ECDSA P-256, tls-crypt, OpenSSL 3 extensions)..."
  openvpn_openssl_extfile "$dir"
  openssl ecparam -genkey -name prime256v1 -out "$dir/ca.key" \
    || die "OpenSSL: cannot generate CA key (install openssl)"
  openvpn_create_ca_cert "$dir"

  openssl ecparam -genkey -name prime256v1 -out "$dir/server.key" \
    || die "OpenSSL: cannot generate server key"
  openvpn_sign_server_cert "$dir"

  openssl ecparam -genkey -name prime256v1 -out "$dir/client.key" \
    || die "OpenSSL: cannot generate client key"
  openvpn_sign_client_cert "$dir"

  if openvpn --genkey tls-crypt "$dir/tc.key" 2>/dev/null; then
    :
  else
    openvpn --genkey secret "$dir/tc.key" \
      || die "OpenVPN: cannot generate tls-crypt key (tc.key)"
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

openvpn_show_pki_fingerprint() {
  local pki_dir="$1"
  local tls="tc.key"
  [[ -f "${pki_dir}/tc.key" ]] || tls="ta.key"
  blank
  info "PKI fingerprint — must match on client after credential copy:"
  md5sum "${pki_dir}/ca.crt" "${pki_dir}/${tls}" 2>/dev/null | sed 's/^/    /'
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
  local ssh_user="${4:-root}" ssh_port="${5:-22}" auth_mode="${6:-key}"
  local remote_pki="${INSTALL_DIR}/pki/${name}"
  local remote_export="${remote_pki}/export"
  local -a ssh_opts=(-p "$ssh_port" -o ConnectTimeout=30 -o StrictHostKeyChecking=accept-new)
  local -a scp_opts=(-P "$ssh_port" -o ConnectTimeout=30 -o StrictHostKeyChecking=accept-new)
  local ssh_err

  [[ "$auth_mode" == "key" ]] && ssh_opts+=(-o BatchMode=yes) && scp_opts+=(-o BatchMode=yes)

  ensure_ssh_deps
  mkdir -p "$pki_dir"
  chmod 700 "$pki_dir"

  blank
  if [[ "$auth_mode" == "password" ]]; then
    info "SSH/SCP from ${ssh_user}@${server_host} — enter server password when prompted..."
  else
    info "Fetching client credentials from ${ssh_user}@${server_host} (SSH key)..."
  fi

  ssh_err=$(mktemp /tmp/virlink-ssh.XXXXXX)
  if ! ssh "${ssh_opts[@]}" "${ssh_user}@${server_host}" "test -d '${remote_pki}'" 2>"$ssh_err"; then
    if grep -qiE 'permission denied|publickey' "$ssh_err"; then
      rm -f "$ssh_err"
      die "SSH login failed (no key / wrong password). Use ${C}easy HTTP download${NC} instead — no SSH needed."
    fi
    if grep -qiE 'connection refused|timed out|no route' "$ssh_err"; then
      rm -f "$ssh_err"
      die "Cannot reach ${server_host}:${ssh_port} — check IP, firewall, and sshd."
    fi
    rm -f "$ssh_err"
    die "No PKI on server at ${remote_pki} — run OpenVPN setup on the server first."
  fi
  rm -f "$ssh_err"

  if ssh "${ssh_opts[@]}" "${ssh_user}@${server_host}" "test -d '${remote_export}'"; then
    scp "${scp_opts[@]}" -r "${ssh_user}@${server_host}:${remote_export}/." "${pki_dir}/" \
      || die "SCP failed"
  else
    local f tls_key="tc.key"
    ssh "${ssh_opts[@]}" "${ssh_user}@${server_host}" "test -f '${remote_pki}/tc.key'" \
      || tls_key="ta.key"
    for f in ca.crt client.crt client.key "$tls_key"; do
      scp "${scp_opts[@]}" "${ssh_user}@${server_host}:${remote_pki}/${f}" "${pki_dir}/${f}" \
        || die "Failed to fetch ${f}"
    done
  fi

  openvpn_strip_server_secrets "$pki_dir"
  ok "PKI fetched from ${server_host} via SSH"
}

openvpn_stop_bundle_server() {
  local name="$1"
  local unit="virlink-bundle-${name}"
  local pidfile="/var/run/virlink/bundle-${name}.pid"
  local metadir="/var/run/virlink/bundle-${name}.meta"

  systemctl stop "$unit" 2>/dev/null || true
  rm -f "/etc/systemd/system/${unit}.service"
  systemctl daemon-reload 2>/dev/null || true

  if [[ -f "$pidfile" ]]; then
    local pid
    pid=$(cat "$pidfile" 2>/dev/null || true)
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    rm -f "$pidfile"
  fi
  if [[ -f "${metadir}/serve.dir" ]]; then
    rm -rf "$(cat "${metadir}/serve.dir" 2>/dev/null)" 2>/dev/null || true
  fi
  if [[ -f "${metadir}/bundle.tgz" ]]; then
    rm -f "$(cat "${metadir}/bundle.tgz" 2>/dev/null)" 2>/dev/null || true
  fi
  rm -rf "$metadir"
}

openvpn_verify_bundle_local() {
  local port="$1" token="$2"
  local url="http://127.0.0.1:${port}/${token}/bundle.tar.gz"
  sleep 1
  if curl -fsSL --connect-timeout 5 --max-time 30 "$url" -o /dev/null 2>/dev/null; then
    ok "Local download test passed (${url})"
    return 0
  fi
  warn "Local HTTP test failed — bundle server may not be running"
  return 1
}

openvpn_start_bundle_server() {
  local name="$1" pki_dir="$2" port="${3:-$OPENVPN_BUNDLE_PORT}"
  local export_dir="${pki_dir}/export"
  local token serve_root bundle meta="/var/run/virlink/bundle-${name}.meta"
  local unit unit_file
  unit="virlink-bundle-${name}"
  unit_file="/etc/systemd/system/${unit}.service"
  local py_bin log="/var/log/virlink/bundle-${name}.log"
  local try_port started=0

  require_cmd python3
  openvpn_export_client_bundle "$pki_dir" || die "Cannot create client export bundle"
  openvpn_stop_bundle_server "$name"
  mkdir -p /var/run/virlink "$meta" /var/log/virlink

  token=$(openssl rand -hex 4 2>/dev/null || tr -dc 'a-f0-9' </dev/urandom | head -c 8)
  py_bin=$(command -v python3)

  for try_port in "$port" 8765 8080 8888 9443; do
    serve_root=$(mktemp -d "/tmp/virlink-serve-${name}.XXXXXX")
    bundle="${serve_root}/bundle.tar.gz"
    mkdir -p "${serve_root}/${token}"
    tar -czf "$bundle" -C "$export_dir" .
    cp "$bundle" "${serve_root}/${token}/bundle.tar.gz"

    cat > "$unit_file" << EOF
[Unit]
Description=virlink OpenVPN credential download (${name})
After=network.target

[Service]
Type=simple
WorkingDirectory=${serve_root}
ExecStart=${py_bin} -m http.server ${try_port} --bind 0.0.0.0
StandardOutput=append:${log}
StandardError=append:${log}
Restart=no
RuntimeMaxSec=${OPENVPN_BUNDLE_TTL}

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    if systemctl start "$unit" 2>/dev/null && systemctl is-active --quiet "$unit"; then
      if openvpn_verify_bundle_local "$try_port" "$token"; then
        port="$try_port"
        started=1
        break
      fi
    fi
    systemctl stop "$unit" 2>/dev/null || true
    rm -f "$unit_file"
    rm -rf "$serve_root"
    systemctl daemon-reload 2>/dev/null || true
  done

  (( started )) || die "Could not start HTTP download server — use SSH password on client instead"

  echo "$token" > "${meta}/token"
  echo "$port" > "${meta}/port"
  echo "$serve_root" > "${meta}/serve.dir"
  echo "$bundle" > "${meta}/bundle.tgz"
  systemctl show -p MainPID --value "$unit" > "/var/run/virlink/bundle-${name}.pid" 2>/dev/null || true

  (
    sleep "$OPENVPN_BUNDLE_TTL"
    openvpn_stop_bundle_server "$name"
  ) &

  OPENVPN_BUNDLE_TOKEN="$token"
  OPENVPN_BUNDLE_PORT="$port"
}

openvpn_allow_bundle_firewall() {
  local port="${1:-$OPENVPN_BUNDLE_PORT}"
  openvpn_allow_bundle_firewall_port "$port"
}

openvpn_allow_bundle_firewall_port() {
  local port="${1:-$OPENVPN_BUNDLE_PORT}"

  if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -qi 'Status: active'; then
    info "Opening UFW TCP/${port}..."
    ufw allow "${port}/tcp" comment 'virlink openvpn bundle' >/dev/null 2>&1 || true
  fi

  if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
    firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi

  if command -v iptables &>/dev/null; then
    if ! iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null; then
      iptables -I INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
    fi
  fi
}

wireguard_allow_firewall_port() {
  local port="$1"
  [[ -n "$port" ]] || return 0

  if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -qi 'Status: active'; then
    info "Opening UFW UDP/${port} (WireGuard)..."
    ufw allow "${port}/udp" comment 'virlink wireguard' >/dev/null 2>&1 || true
  fi

  if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
    firewall-cmd --permanent --add-port="${port}/udp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi

  if command -v iptables &>/dev/null; then
    if ! iptables -C INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null; then
      iptables -I INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null || true
    fi
  fi
}

openvpn_save_bundle_info() {
  local pki_dir="$1" server_ip="$2" name="$3"
  local port="${OPENVPN_BUNDLE_PORT:-8765}"
  local token="${OPENVPN_BUNDLE_TOKEN:-}"
  local f="${pki_dir}/export/COPY_TO_CLIENT.txt"
  [[ -n "$token" ]] || return 0
  cat > "$f" << EOF
# virlink OpenVPN — copy these values on the CLIENT (easy HTTP download)
server_ip=${server_ip}
port=${port}
token=${token}
url=http://${server_ip}:${port}/${token}/bundle.tar.gz
expires_minutes=$(( OPENVPN_BUNDLE_TTL / 60 ))
tunnel_name=${name}
EOF
  chmod 600 "$f"
}

openvpn_show_bundle_instructions() {
  local server_ip="$1" name="$2"
  local port="${OPENVPN_BUNDLE_PORT:-8765}"
  local token="${OPENVPN_BUNDLE_TOKEN:-????????}"
  blank
  tty_line -e "  ${BOLD}${G}━━━━━━━━━━ COPY TO CLIENT ━━━━━━━━━━${NC}"
  tty_line -e "  ${BOLD}Server IP${NC}  ${W}${server_ip}${NC}"
  tty_line -e "  ${BOLD}Port${NC}       ${W}${port}${NC}"
  tty_line -e "  ${BOLD}Token${NC}      ${W}${token}${NC}  ${DIM}(enter exactly on client)${NC}"
  tty_line -e "  ${BOLD}Expires${NC}    ${W}$(( OPENVPN_BUNDLE_TTL / 60 )) minutes${NC}"
  sep_thin
  tty_line -e "  On ${BOLD}client${NC}: virlink-setup → openvpn → client → ${C}easy HTTP download${NC}"
  tty_line -e "  ${DIM}One-liner on client:${NC}"
  tty_line -e "  ${W}curl -fsSL http://${server_ip}:${port}/${token}/bundle.tar.gz | sudo tar -xzf - -C ${INSTALL_DIR}/pki/${name}/${NC}"
  sep_thin
  tty_line -e "  ${Y}${BOLD}Hetzner / cloud firewall:${NC} allow inbound ${BOLD}TCP ${port}${NC} from client IP"
  tty_line -e "  ${DIM}Hetzner: Cloud Console → Firewalls → add rule TCP ${port}${NC}"
  tty_line -e "  ${DIM}If download fails on client: choose ${C}ssh-password${NC} (uses port 22, no keys needed)"
  sep_thin
  info "Token saved: ${INSTALL_DIR}/pki/${name}/export/COPY_TO_CLIENT.txt"
  info "Download log: /var/log/virlink/bundle-${name}.log"
}

openvpn_fetch_pki_via_http() {
  local name="$1" server_host="$2" pki_dir="$3"
  local port token _p _t

  require_cmd curl
  require_cmd tar
  mkdir -p "$pki_dir"
  chmod 700 "$pki_dir"

  blank
  info "Easy download — copy ${BOLD}Port${NC} and ${BOLD}Token${NC} from the server screen."
  info "Server must show ${C}COPY TO CLIENT${NC} after you run setup there (option easy starts automatically)."
  prompt _p "Server download port" "$OPENVPN_BUNDLE_PORT"
  prompt _t "Download token (8 chars from server — not a placeholder)" ""
  port="$_p"
  token="$_t"
  [[ -n "$token" ]] || die "Token is required — start download on server first."

  info "Downloading from http://${server_host}:${port}/${token}/bundle.tar.gz ..."
  if curl -fsSL --connect-timeout 20 --max-time 120 \
      "http://${server_host}:${port}/${token}/bundle.tar.gz" \
      | tar -xzf - -C "$pki_dir" 2>/dev/null; then
    openvpn_strip_server_secrets "$pki_dir"
    ok "PKI downloaded from server (HTTP)"
    return 0
  fi

  blank
  warn "HTTP download failed (timeout = port ${port} blocked or server link expired)."
  warn "Hetzner/AWS: open TCP/${port} in cloud firewall, or use SSH password (port 22)."
  if confirm "Try SSH download with server root password?"; then
    openvpn_prompt_ssh
    openvpn_fetch_pki_from_server "$name" "$server_host" "$pki_dir" \
      "$OPENVPN_SSH_USER" "$OPENVPN_SSH_PORT" password
    openvpn_strip_server_secrets "$pki_dir"
    ok "PKI fetched via SSH password"
    return 0
  fi
  die "Download failed — on server re-run setup for new token, or use ssh-password method"
}

openvpn_show_manual_copy_help() {
  local name="$1" server_host="$2" pki_dir="$3"
  blank
  echo -e "  ${BOLD}Manual copy${NC}"
  sep_thin
  echo -e "  On ${BOLD}server${NC}, files are in:"
  echo -e "    ${W}${INSTALL_DIR}/pki/${name}/export/${NC}"
  echo -e "  Copy ${W}ca.crt client.crt client.key tc.key${NC} to client:"
  echo -e "    ${W}${pki_dir}/${NC}"
  echo
  echo -e "  ${DIM}Example (enter password when asked):${NC}"
  echo -e "    scp -r root@${server_host}:${INSTALL_DIR}/pki/${name}/export/* ${pki_dir}/"
  sep_thin
  press_enter
}

openvpn_acquire_client_pki() {
  local name="$1" server_host="$2" pki_dir="$3"
  local method_raw method

  if [[ -f "${pki_dir}/ca.crt" ]]; then
    openvpn_require_client_pki "$pki_dir"
    openvpn_show_pki_fingerprint "$pki_dir"
    return 0
  fi

  blank
  warn "Client PKI not found locally."
  info "Choose how to get credentials from the server (client certs only — no server private keys)."

  pick method_raw "Get credentials from server" \
    "ssh-password — SSH/SCP (recommended on Hetzner, type server password)" \
    "easy — HTTP download (needs cloud firewall TCP port open)" \
    "ssh-key — SSH/SCP (automatic, needs ssh-copy-id first)" \
    "manual — files already copied / copy by hand"
  method="$(label_key "$method_raw")"

  case "$method" in
    ssh-password)
      openvpn_prompt_ssh
      openvpn_fetch_pki_from_server "$name" "$server_host" "$pki_dir" \
        "$OPENVPN_SSH_USER" "$OPENVPN_SSH_PORT" password
      ;;
    easy)
      openvpn_fetch_pki_via_http "$name" "$server_host" "$pki_dir"
      ;;
    ssh-key)
      openvpn_prompt_ssh
      openvpn_fetch_pki_from_server "$name" "$server_host" "$pki_dir" \
        "$OPENVPN_SSH_USER" "$OPENVPN_SSH_PORT" key
      ;;
    manual)
      openvpn_show_manual_copy_help "$name" "$server_host" "$pki_dir"
      ;;
    *)
      die "Unknown transfer method: $method"
      ;;
  esac
  openvpn_require_client_pki "$pki_dir"
  openvpn_show_pki_fingerprint "$pki_dir"
}

openvpn_server_send_credentials() {
  local name="$1" client_host="$2" pki_dir="$3" server_ip="$4"

  blank
  info "Starting credential download server for client ${client_host}..."
  openvpn_start_bundle_server "$name" "$pki_dir"
  openvpn_allow_bundle_firewall "$OPENVPN_BUNDLE_PORT"
  openvpn_save_bundle_info "$pki_dir" "$server_ip" "$name"
  ok "Download server running on TCP ${OPENVPN_BUNDLE_PORT}"
  openvpn_show_bundle_instructions "$server_ip" "$name"
  warn "If download fails: allow TCP ${OPENVPN_BUNDLE_PORT} on cloud firewall (Hetzner/AWS security group)"

  if confirm "Use SSH or manual copy instead?"; then
    local method_raw method
    pick method_raw "Alternative transfer" \
      "ssh-password — push via SSH (password prompt)" \
      "ssh-key — push via SSH (needs ssh-copy-id)" \
      "manual — show scp commands only"
    method="$(label_key "$method_raw")"
    case "$method" in
      ssh-password)
        openvpn_prompt_ssh
        openvpn_push_client_bundle "$name" "$client_host" "$pki_dir" \
          "$OPENVPN_SSH_USER" "$OPENVPN_SSH_PORT" password
        ;;
      ssh-key)
        openvpn_prompt_ssh
        openvpn_push_client_bundle "$name" "$client_host" "$pki_dir" \
          "$OPENVPN_SSH_USER" "$OPENVPN_SSH_PORT" key
        ;;
      manual)
        openvpn_show_manual_copy_help "$name" "$client_host" "$pki_dir"
        ;;
    esac
  fi

  blank
  info "Keep this session open until the client downloads (or within $(( OPENVPN_BUNDLE_TTL / 60 )) min)."
  press_enter
}

openvpn_push_client_bundle() {
  local name="$1" client_host="$2" pki_dir="$3"
  local ssh_user="${4:-root}" ssh_port="${5:-22}" auth_mode="${6:-key}"
  local export_dir="${pki_dir}/export"
  local remote_dir="${INSTALL_DIR}/pki/${name}"
  local -a ssh_opts=(-p "$ssh_port" -o ConnectTimeout=30 -o StrictHostKeyChecking=accept-new)
  local -a scp_opts=(-P "$ssh_port" -o ConnectTimeout=30 -o StrictHostKeyChecking=accept-new)

  [[ "$auth_mode" == "key" ]] && ssh_opts+=(-o BatchMode=yes) && scp_opts+=(-o BatchMode=yes)

  ensure_ssh_deps
  openvpn_export_client_bundle "$pki_dir" || die "Export bundle missing — regenerate PKI on server"

  blank
  if [[ "$auth_mode" == "password" ]]; then
    info "Pushing to ${ssh_user}@${client_host} — enter client password when prompted..."
  else
    info "Pushing client credentials to ${ssh_user}@${client_host}..."
  fi

  ssh "${ssh_opts[@]}" "${ssh_user}@${client_host}" \
    "mkdir -p '${remote_dir}' && chmod 700 '${remote_dir}'" \
    || die "SSH to client failed"

  scp "${scp_opts[@]}" -r "${export_dir}/." "${ssh_user}@${client_host}:${remote_dir}/" \
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
    [[ "$role" == "server" ]] && echo "dh none"
    cat << EOF
tls-groups X25519:prime256v1
${tls_line}
tls-version-min 1.2
EOF
  elif [[ -f "${dir}/dh.pem" ]]; then
    [[ "$role" == "server" ]] && echo "dh dh.pem"
    cat << EOF
${tls_line}
tls-version-min 1.2
EOF
  else
    die "Incomplete PKI in ${dir} — missing tc.key or dh.pem"
  fi
}

# OpenVPN 2.6+ requires tcp-server / tcp-client (plain "tcp" is ambiguous).
openvpn_openvpn_proto() {
  local base="$1" role="$2"
  case "$base" in
    tcp)
      [[ "$role" == "server" ]] && echo "tcp-server" || echo "tcp-client"
      ;;
    udp) echo "udp" ;;
    *)   echo "$base" ;;
  esac
}

openvpn_write_server_conf() {
  local dir="$1" port="$2" proto="$3" client_ip="$4" server_ip="$5" mtu="$6" dev="$7" perf="$8"
  local tun_mtu="$9" mssfix="${10}" out="${11:-${dir}/server.conf}" use_dco="${12:-0}"
  local ovpn_proto
  ovpn_proto="$(openvpn_openvpn_proto "$proto" server)"
  cat > "$out" << EOF
# virlink OpenVPN — server (site-to-site, ${perf} profile, ${proto})
port ${port}
proto ${ovpn_proto}
dev ${dev}
dev-type tun
persist-key
persist-tun
ca ca.crt
cert server.crt
key server.key
EOF
  if [[ "$use_dco" == "1" ]] && openvpn_binary_supports_dco; then
    echo "enable-dco" >> "$out"
  else
    cat >> "$out" << EOF
user nobody
group nogroup
EOF
  fi
  openvpn_write_crypto_block "$dir" server >> "$out"
  cat >> "$out" << EOF
tls-server
ifconfig ${server_ip} ${client_ip}
EOF
  openvpn_perf_block "$perf" "$proto" "$tun_mtu" "$mssfix" >> "$out"
  if [[ "$proto" == "udp" ]]; then
    echo "explicit-exit-notify 1" >> "$out"
  fi
}

openvpn_write_client_conf() {
  local dir="$1" port="$2" proto="$3" remote_ip="$4" client_ip="$5" server_ip="$6" mtu="$7" dev="$8" perf="$9"
  local tun_mtu="${10}" mssfix="${11}" out="${12:-${dir}/client.conf}" use_dco="${13:-0}"
  local ovpn_proto
  ovpn_proto="$(openvpn_openvpn_proto "$proto" client)"
  cat > "$out" << EOF
# virlink OpenVPN — client (site-to-site p2p, ${perf} profile, ${proto})
dev ${dev}
dev-type tun
proto ${ovpn_proto}
remote ${remote_ip} ${port}
nobind
tls-client
connect-timeout 30
connect-retry-max 5
persist-key
persist-tun
ca ca.crt
cert client.crt
key client.key
EOF
  if [[ "$use_dco" == "1" ]] && openvpn_binary_supports_dco; then
    echo "enable-dco" >> "$out"
  fi
  openvpn_write_crypto_block "$dir" client >> "$out"
  cat >> "$out" << EOF
remote-cert-tls server
ifconfig ${client_ip} ${server_ip}
EOF
  openvpn_perf_block "$perf" "$proto" "$tun_mtu" "$mssfix" >> "$out"
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
  local use_dco=0 dco_toml dco_raw
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

  ensure_openvpn_deps
  pki_dir="${INSTALL_DIR}/pki/${name}"
  mkdir -p "$pki_dir"

  if [[ "$mode" == "server" ]]; then
    openvpn_gen_pki "$pki_dir"
  else
    openvpn_acquire_client_pki "$name" "$remote_ip" "$pki_dir"
  fi

  blank
  info "Multi-core bandwidth on one overlay IP requires DCO (OpenVPN 2.6+ + ovpn-dco kernel module)."
  if openvpn_version_at_least 2 6 && ensure_openvpn_dco; then
    pick dco_raw "Data Channel Offload (DCO)" \
      "yes — multi-core on single peer IP (recommended)" \
      "no — user-space crypto only (~1 core per flow)"
    if [[ "$(label_key "$dco_raw")" == "yes" ]]; then
      use_dco=1
      ok "DCO enabled — one tunnel, one overlay IP, crypto spread across CPU cores"
    fi
  else
    warn "DCO not available (need OpenVPN 2.6+ and ovpn-dco kernel module)"
    warn "Without DCO, use iperf3 -P for parallel flows — not the same as multi-core on one IP"
  fi

  dco_toml="false"
  [[ "$use_dco" -eq 1 ]] && dco_toml="true"

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
    openvpn_write_server_conf "$pki_dir" "$port" "$proto" "$client_ip" "$server_ip" "$mtu" "$dev" "$perf" "$tun_mtu" "$mssfix" "$ovpn_conf" "$use_dco"
    openvpn_write_client_conf "$pki_dir" "$port" "$proto" "$local_ip" "$client_ip" "$server_ip" "$mtu" "$dev" "$perf" "$tun_mtu" "$mssfix" "${pki_dir}/client.conf" "$use_dco"
    ok "Wrote ${ovpn_conf} (${perf}, ${proto}, dco=${dco_toml})"
  else
    ovpn_conf="${pki_dir}/client.conf"
    openvpn_write_client_conf "$pki_dir" "$port" "$proto" "$remote_ip" "$client_ip" "$server_ip" "$mtu" "$dev" "$perf" "$tun_mtu" "$mssfix" "$ovpn_conf" "$use_dco"
    ok "Wrote ${ovpn_conf} (${perf}, ${proto}, dco=${dco_toml})"
    blank
    warn "Start the OpenVPN SERVER tunnel first (peer ${remote_ip})."
    warn "Firewall: allow ${proto}/${port} from this host → server (Hetzner cloud firewall too)."
    info "If tunnel fails: tail -30 /var/log/virlink/${name}-openvpn.log"
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
dco    = ${dco_toml}

[security]
encryption = true
EOF
  write_openvpn_tuning "$cfg" "$perf"
  add_forward_section "$cfg" "$mode"
  LAST_CFG_PATH="$cfg"

  if [[ "$mode" == "server" ]]; then
    local pki="${INSTALL_DIR}/pki/${name}" tls_key="tc.key"
    [[ -f "${pki_dir}/tc.key" ]] || tls_key="ta.key"
    virlink_server_write_manual_client "$name" "$mode" "$remote_ip" "$local_ip" "$cfg" "openvpn" "$port" \
      "${pki}/ca.crt" "${pki_dir}/ca.crt" 644 \
      "${pki}/client.crt" "${pki_dir}/client.crt" 644 \
      "${pki}/client.key" "${pki_dir}/client.key" 600 \
      "${pki}/${tls_key}" "${pki_dir}/${tls_key}" 600 \
      "${pki}/client.conf" "${pki_dir}/client.conf" 644
    blank
    info "Privacy: CA/server private keys remain on this host only."
    info "Client install: ${W}${MANUAL_CLIENT_CONF_DIR}/${remote_ip}-openvpn-${port}.txt${NC} or export/ bundle."
    openvpn_server_send_credentials "$name" "$remote_ip" "$pki_dir" "$local_ip"
    openvpn_show_pki_fingerprint "$pki_dir"
    blank
    warn "Start this server tunnel before the client: virlink-setup → Start tunnel → ${name}"
    warn "Firewall: allow ${proto}/${port} from client ${remote_ip}"
  fi

  blank
  warn "Firewall: allow ${proto}/${port} between ${local_ip} and ${remote_ip}"
  if [[ "$mode" == "server" ]]; then
    info "Client overlay IP: ${client_ip}  ·  Server overlay IP: ${server_ip}"
  fi
  info "OpenVPN: tun-mtu ${tun_mtu}  mssfix ${mssfix}  profile ${perf}"
}

# ── Client install scripts (/root/manual-client-conf/) ────────────────────────

virlink_manual_client_basename() {
  local client_ip="$1" protocol="$2" port_num="$3"
  echo "${client_ip}-${protocol}-${port_num}.txt"
}

virlink_manual_client_script_path() {
  echo "${MANUAL_CLIENT_CONF_DIR}/$(virlink_manual_client_basename "$1" "$2" "$3")"
}

virlink_script_cat_file() {
  local script="$1" dest="$2" src="$3" mode="${4:-644}"
  {
    echo ""
    echo "cat << 'EOF' > ${dest}"
    cat "$src"
    # Source may lack trailing newline (e.g. pin.sha256) — keep heredoc terminator on its own line.
    echo ""
    echo "EOF"
    echo "chmod ${mode} ${dest}"
  } >> "$script"
}

virlink_make_client_toml() {
  local server_cfg="$1" out="$2" client_pub="$3" server_pub="$4"
  cp "$server_cfg" "$out"
  sed -i \
    -e 's/mode      = "server"/mode      = "client"/' \
    -e "s|^local_ip  = .*|local_ip  = \"${client_pub}\"|" \
    -e "s|^remote_ip = .*|remote_ip = \"${server_pub}\"|" \
    -e 's|/server\.conf|/client.conf|g' \
    -e 's|/server\.yaml|/client.yaml|g' \
    -e 's|/wg-server\.conf|/wg-client.conf|g' \
    "$out"
  if ! grep -q '^\[forward\]' "$out"; then
    add_forward_section "$out" client
  fi
}

virlink_client_install_script_begin() {
  local out="$1" client_ip="$2" title="$3" name="$4" script_basename="$5"
  cat > "$out" << EOF
#!/bin/bash
# virlink ${title} — run on client ${client_ip}
# Tunnel: ${name}
# Copy to client, then: bash manual-client-conf/${script_basename}

set -euo pipefail
mkdir -p '${CONFIGS_DIR}'
mkdir -p '${INSTALL_DIR}/pki/${name}'
chmod 700 '${INSTALL_DIR}/pki/${name}' 2>/dev/null || true
EOF
}

virlink_client_install_script_finish() {
  local script="$1" name="$2" client_cfg="$3" server_ip="$4" title="$5"
  cat >> "$script" << EOF

echo "✓ virlink ${title} client files installed for tunnel '${name}'"
echo "  Start server on ${server_ip} first."

TUNNEL_NAME='${name}'
CLIENT_CFG='${client_cfg}'
SVC='virlink-${name}'
VIRLINK_BIN='${VIRLINK_BIN}'
SETUP_BIN='/usr/local/bin/virlink-setup'
LOGS_DIR='${LOGS_DIR}'

if [[ ! -f "\$CLIENT_CFG" ]]; then
  echo "✗ Expected config missing: \$CLIENT_CFG"
  exit 1
fi

svc_exists=0
if [[ -f "/etc/systemd/system/\${SVC}.service" ]]; then
  svc_exists=1
elif systemctl list-unit-files "\${SVC}.service" &>/dev/null; then
  systemctl list-unit-files "\${SVC}.service" 2>/dev/null | grep -q "^\${SVC}.service" && svc_exists=1
fi

if [[ \$svc_exists -eq 0 ]]; then
  echo ""
  read -r -p "? Config found (\${CLIENT_CFG}) but no systemd service (\${SVC}). Create and start tunnel? [y/N]: " _ans
  if [[ "\${_ans,,}" == "y" ]]; then
    if [[ -x "\$SETUP_BIN" ]]; then
      "\$SETUP_BIN" start "\$TUNNEL_NAME"
    elif [[ -x "\$VIRLINK_BIN" ]]; then
      mkdir -p "\$LOGS_DIR"
      cat > "/etc/systemd/system/\${SVC}.service" << SVC_EOF
[Unit]
Description=virlink tunnel — \${TUNNEL_NAME}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=\${VIRLINK_BIN} -c \${CLIENT_CFG}
Restart=on-failure
RestartSec=10
StandardOutput=append:\${LOGS_DIR}/\${TUNNEL_NAME}.log
StandardError=append:\${LOGS_DIR}/\${TUNNEL_NAME}.log

[Install]
WantedBy=multi-user.target
SVC_EOF
      systemctl daemon-reload
      systemctl enable "\$SVC"
      systemctl start "\$SVC"
      sleep 1
      if systemctl is-active "\$SVC" &>/dev/null; then
        echo "✓ Tunnel '\$TUNNEL_NAME' running (service: \$SVC)"
      else
        echo "✗ Failed to start — check: journalctl -u \$SVC -n 30"
        exit 1
      fi
    else
      echo "✗ virlink not installed — run setup.sh first, then: virlink -c \$CLIENT_CFG"
      exit 1
    fi
  else
    echo "  Skipped. Start manually: virlink -c \$CLIENT_CFG"
    echo "  Or after install: virlink-setup start \$TUNNEL_NAME"
  fi
else
  echo "  Service \$SVC already exists — start with: systemctl start \$SVC"
fi
EOF
}

virlink_emit_manual_client_install() {
  local name="$1" client_ip="$2" server_ip="$3" tunnel_type="$4" port_num="$5"
  local client_toml_src="$6"
  shift 6

  mkdir -p "$MANUAL_CLIENT_CONF_DIR"
  local basename script_path client_toml_dest
  basename="$(virlink_manual_client_basename "$client_ip" "$tunnel_type" "$port_num")"
  script_path="$(virlink_manual_client_script_path "$client_ip" "$tunnel_type" "$port_num")"
  client_toml_dest="${CONFIGS_DIR}/${name}.toml"

  virlink_client_install_script_begin "$script_path" "$client_ip" "$tunnel_type" "$name" "$basename"
  virlink_script_cat_file "$script_path" "$client_toml_dest" "$client_toml_src" 644
  while (($# >= 3)); do
    virlink_script_cat_file "$script_path" "$1" "$2" "${3:-644}"
    shift 3
  done
  virlink_client_install_script_finish "$script_path" "$name" "$client_toml_dest" "$server_ip" "$tunnel_type"

  chmod 644 "$script_path"
  ok "Client install script: ${script_path}"
  info "On client: bash manual-client-conf/${basename}"
}

virlink_server_write_manual_client() {
  local name="$1" mode="$2" client_ip="$3" server_ip="$4" server_cfg="$5"
  local tunnel_type="$6" port_num="${7:-0}"
  shift 7
  [[ "$mode" == "server" ]] || return 0

  local staging="${MANUAL_CLIENT_CONF_DIR}/.build/${name}"
  local client_toml="${staging}/client.toml"
  mkdir -p "$staging"
  virlink_make_client_toml "$server_cfg" "$client_toml" "$client_ip" "$server_ip"
  virlink_emit_manual_client_install "$name" "$client_ip" "$server_ip" "$tunnel_type" "$port_num" \
    "$client_toml" "$@"
}

# ── Hysteria2 helpers ──────────────────────────────────────────────────────────

hysteria2_overlay_ips() {
  openvpn_overlay_ips "$@"
}

hysteria2_gen_tls_cert() {
  local dir="$1" server_ip="$2"
  [[ -n "$server_ip" ]] || die "server IP required for TLS certificate"
  if openssl req -new -x509 -days 3650 -key "$dir/server.key" -out "$dir/server.crt" \
      -subj "/CN=${server_ip}" \
      -addext "subjectAltName=IP:${server_ip}" 2>/dev/null; then
    return 0
  fi
  cat > "${dir}/openssl-hy2.cnf" << EOF
[ req ]
default_bits = 256
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3

[ dn ]
CN = ${server_ip}

[ v3 ]
subjectAltName = IP:${server_ip}
EOF
  openssl req -new -x509 -days 3650 -key "$dir/server.key" -out "$dir/server.crt" \
    -config "${dir}/openssl-hy2.cnf" \
    || die "OpenSSL: cannot create server certificate"
}

hysteria2_compute_pin() {
  local dir="$1"
  [[ -f "${dir}/server.crt" ]] || return 0
  openssl x509 -noout -fingerprint -sha256 -in "${dir}/server.crt" 2>/dev/null \
    | sed 's/^sha256 Fingerprint=//' | tr -d '\n' > "${dir}/pin.sha256"
  printf '\n' >> "${dir}/pin.sha256"
  chmod 644 "${dir}/pin.sha256"
}

hysteria2_ensure_server_tls() {
  local dir="$1" server_ip="$2"
  local regen=0 cp kp
  [[ -f "$dir/server.key" && -f "$dir/server.crt" ]] || regen=1
  if [[ $regen -eq 0 ]]; then
    cp=$(openssl x509 -in "$dir/server.crt" -noout -pubkey 2>/dev/null | openssl md5 2>/dev/null | awk '{print $NF}')
    kp=$(openssl ec -in "$dir/server.key" -pubout 2>/dev/null | openssl md5 2>/dev/null | awk '{print $NF}')
    [[ -n "$cp" && "$cp" == "$kp" ]] || regen=1
  fi
  if [[ $regen -eq 1 ]]; then
    info "Generating server TLS key (stays on server — client uses password only)..."
    openssl ecparam -genkey -name prime256v1 -out "$dir/server.key" \
      || die "OpenSSL: cannot generate server key"
    hysteria2_gen_tls_cert "$dir" "$server_ip"
    hysteria2_compute_pin "$dir"
    chmod 600 "$dir/server.key"
    chmod 644 "$dir/server.crt"
  fi
  hysteria2_compute_pin "$dir"
}

hysteria2_gen_credentials() {
  local dir="$1" server_ip="${2:-}"
  mkdir -p "$dir/export"
  chmod 700 "$dir"
  hysteria2_ensure_server_tls "$dir" "$server_ip"
  if [[ ! -f "$dir/password" ]]; then
    openssl rand -hex 16 > "$dir/password"
    chmod 600 "$dir/password"
    ok "Auth password generated"
  else
    ok "Auth password already exists"
  fi
}

hysteria2_save_export_info() {
  local dir="$1" server_ip="$2" port="$3" name="$4"
  local f="${dir}/export/COPY_TO_CLIENT.txt"
  cat > "$f" << EOF
# virlink Hysteria2 — copy to CLIENT
# Server: ${server_ip}:${port}  ·  tunnel: ${name}

Copy to ${INSTALL_DIR}/pki/${name}/ on the client:
  password
  pin.sha256
  obfs.password   (only if server uses salamander obfs)

Optional (instead of pinSHA256): server.crt for tls.ca pinning

Then run: virlink-setup → client → hysteria2 → same tunnel name

Or use the install script on the server:
  ${MANUAL_CLIENT_CONF_DIR}/<client_ip>-hysteria2-<port>.txt

Or scp:
  scp root@${server_ip}:${dir}/export/password ${INSTALL_DIR}/pki/${name}/
  scp root@${server_ip}:${dir}/export/pin.sha256 ${INSTALL_DIR}/pki/${name}/
  scp root@${server_ip}:${dir}/export/obfs.password ${INSTALL_DIR}/pki/${name}/   # if present
EOF
  chmod 644 "$f"
}

hysteria2_write_server_yaml() {
  local dir="$1" port="$2" server_ip="$3" mtu="$4" dev="$5" obfs="$6"
  local pass; pass="$(tr -d '\n' < "${dir}/password")"
  cat > "${dir}/server.yaml" << EOF
# virlink Hysteria2 — server (QUIC proxy + virlink kernel TUN)
listen: 0.0.0.0:${port}

tls:
  cert: server.crt
  key: server.key

auth:
  type: password
  password: ${pass}

masquerade:
  type: proxy
  proxy:
    url: https://www.bing.com
    rewriteHost: true

bandwidth:
  up: 1 gbps
  down: 1 gbps

quic:
  keepAlivePeriod: 10s
  maxIdleTimeout: 60s
EOF
  if [[ -n "$obfs" ]]; then
    echo "$obfs" > "${dir}/obfs.password"
    chmod 600 "${dir}/obfs.password"
    cat >> "${dir}/server.yaml" << EOF

obfs:
  type: salamander
  salamander:
    password: ${obfs}
EOF
  fi
}

hysteria2_write_client_yaml() {
  local dir="$1" port="$2" remote_ip="$3" client_ip="$4" server_ip="$5" mtu="$6" dev="$7" obfs="$8"
  local wrap_port=$((10000 + port))
  local pass pin=""
  pass="$(tr -d '\n' < "${dir}/password")"
  if [[ -f "${dir}/pin.sha256" ]]; then
    pin="$(tr -d '\n' < "${dir}/pin.sha256")"
  elif [[ -f "${dir}/export/pin.sha256" ]]; then
    pin="$(tr -d '\n' < "${dir}/export/pin.sha256")"
  fi
  [[ -n "$pin" ]] || die "Missing pin.sha256 — re-run server setup or copy export bundle"
  cat > "${dir}/client.yaml" << EOF
# virlink Hysteria2 — client (site-to-site via udpForwarding + kernel TUN)
server: ${remote_ip}:${port}

auth: ${pass}

tls:
  insecure: true
  pinSHA256: ${pin}

bandwidth:
  up: 200 mbps
  down: 200 mbps

quic:
  keepAlivePeriod: 10s
  maxIdleTimeout: 60s

udpForwarding:
  - listen: 127.0.0.1:${wrap_port}
    remote: 127.0.0.1:${wrap_port}
    timeout: 300s
EOF
  if [[ -n "$obfs" ]]; then
    cat >> "${dir}/client.yaml" << EOF

obfs:
  type: salamander
  salamander:
    password: ${obfs}
EOF
  fi
}

hysteria2_export_client_bundle() {
  local dir="$1" server_ip="$2" port="$3" name="$4"
  local export_dir="${dir}/export"
  mkdir -p "$export_dir"
  hysteria2_compute_pin "$dir"
  cp -f "${dir}/password" "${export_dir}/password"
  [[ -f "${dir}/pin.sha256" ]] && cp -f "${dir}/pin.sha256" "${export_dir}/pin.sha256"
  [[ -f "${dir}/obfs.password" ]] && cp -f "${dir}/obfs.password" "${export_dir}/obfs.password"
  chmod 600 "${export_dir}/password"
  [[ -f "${export_dir}/pin.sha256" ]] && chmod 644 "${export_dir}/pin.sha256"
  [[ -f "${export_dir}/obfs.password" ]] && chmod 600 "${export_dir}/obfs.password"
  rm -f "${export_dir}/client.yaml"
  hysteria2_save_export_info "$dir" "$server_ip" "$port" "$name"
  ok "Client export: ${export_dir} (password + pin.sha256)"
}

hysteria2_show_fingerprint() {
  local dir="$1"
  blank
  info "Auth fingerprint — must match on client:"
  md5sum "${dir}/password" 2>/dev/null | sed 's/^/    /'
  [[ -f "${dir}/obfs.password" ]] && md5sum "${dir}/obfs.password" 2>/dev/null | sed 's/^/    /'
  if [[ -f "${dir}/pin.sha256" ]]; then
    info "TLS pinSHA256:"
    sed 's/^/    /' "${dir}/pin.sha256"
  elif [[ -f "${dir}/export/pin.sha256" ]]; then
    info "TLS pinSHA256:"
    sed 's/^/    /' "${dir}/export/pin.sha256"
  fi
}

hysteria2_fetch_from_server() {
  local name="$1" server_host="$2" pki_dir="$3"
  local ssh_user="${4:-root}" ssh_port="${5:-22}"
  local remote="${INSTALL_DIR}/pki/${name}/export"
  local -a scp_opts=(-P "$ssh_port" -o ConnectTimeout=30 -o StrictHostKeyChecking=accept-new)
  ensure_ssh_deps
  mkdir -p "$pki_dir"
  chmod 700 "$pki_dir"
  info "Fetching Hysteria2 password from ${server_host}..."
  scp "${scp_opts[@]}" -r "${ssh_user}@${server_host}:${remote}/." "${pki_dir}/" \
    || die "SCP failed — run Hysteria2 setup on server first"
  [[ -f "${pki_dir}/password" ]] || die "Missing password — re-run server setup"
  [[ -f "${pki_dir}/pin.sha256" ]] || die "Missing pin.sha256 — re-run server setup"
  ok "Credentials copied to ${pki_dir}"
}

hysteria2_acquire_client() {
  local name="$1" server_host="$2" pki_dir="$3"
  if [[ -f "${pki_dir}/password" ]]; then
    hysteria2_show_fingerprint "$pki_dir"
    return 0
  fi
  blank
  warn "Hysteria2 password not found locally."
  info "Client needs ${W}password${NC} + ${W}pin.sha256${NC} (+ obfs.password if enabled)."
  pick method "Get credentials from server" \
    "ssh-password — SCP from server (recommended)" \
    "manual — copy export/ by hand"
  method="$(label_key "$method")"
  case "$method" in
    ssh-password)
      openvpn_prompt_ssh
      hysteria2_fetch_from_server "$name" "$server_host" "$pki_dir" \
        "$OPENVPN_SSH_USER" "$OPENVPN_SSH_PORT"
      ;;
    manual)
      mkdir -p "$pki_dir"
      chmod 700 "$pki_dir"
      blank
      info "Copy from server → client:"
      tty_line -e "  ${W}scp root@${server_host}:${INSTALL_DIR}/pki/${name}/export/password ${pki_dir}/${NC}"
      tty_line -e "  ${W}scp root@${server_host}:${INSTALL_DIR}/pki/${name}/export/pin.sha256 ${pki_dir}/${NC}"
      tty_line -e "  ${W}scp root@${server_host}:${INSTALL_DIR}/pki/${name}/export/obfs.password ${pki_dir}/${NC}  ${DIM}(if obfs enabled)${NC}"
      blank
      while [[ ! -f "${pki_dir}/password" || ! -f "${pki_dir}/pin.sha256" ]]; do
        warn "Missing: ${pki_dir}/password and/or ${pki_dir}/pin.sha256"
        if ! confirm "Copied credentials — check again"; then
          die "Need password + pin.sha256 in ${pki_dir}"
        fi
      done
      ok "Credentials found in ${pki_dir}"
      ;;
    *) die "Unknown method: $method" ;;
  esac
  hysteria2_show_fingerprint "$pki_dir"
}

hysteria2_push_to_client() {
  local name="$1" client_host="$2" pki_dir="$3" server_ip="$4" port="$5"
  local ssh_user="${6:-root}" ssh_port="${7:-22}"
  local export_dir="${pki_dir}/export"
  local remote_dir="${INSTALL_DIR}/pki/${name}"
  local -a ssh_opts=(-p "$ssh_port" -o ConnectTimeout=30 -o StrictHostKeyChecking=accept-new)
  local -a scp_opts=(-P "$ssh_port" -o ConnectTimeout=30 -o StrictHostKeyChecking=accept-new)
  hysteria2_export_client_bundle "$pki_dir" "$server_ip" "$port" "$name"
  ensure_ssh_deps
  ssh "${ssh_opts[@]}" "${ssh_user}@${client_host}" "mkdir -p '${remote_dir}' && chmod 700 '${remote_dir}'" \
    || die "SSH to client failed"
  scp "${scp_opts[@]}" -r "${export_dir}/." "${ssh_user}@${client_host}:${remote_dir}/" \
    || die "SCP to client failed"
  ok "Credentials pushed to ${client_host}:${remote_dir}"
}

gen_hysteria2() {
  local name mode local_ip remote_ip cidr port mtu dev pki_dir hy_conf cfg
  local client_ip server_ip obfs_raw obfs="" hb
  collect_base_inputs name mode local_ip remote_ip cidr
  blank
  info "Hysteria2 uses QUIC/UDP — fast and resistant to many filters."
  prompt port "Hysteria2 port (QUIC)" "443"
  prompt mtu "TUN MTU (overlay)" "1400"
  pick obfs_raw "Salamander obfuscation (optional)" \
    "no — standard HTTP/3 masquerade" \
    "yes — salamander (extra obfuscation password)"
  if [[ "$(label_key "$obfs_raw")" == "yes" ]]; then
    obfs="$(openssl rand -hex 8)"
    info "Obfuscation password: ${obfs}"
  fi
  dev="hy2-tun0"

  ensure_hysteria2_deps
  pki_dir="${INSTALL_DIR}/pki/${name}"
  mkdir -p "$pki_dir"

  if [[ "$mode" == "server" ]]; then
    hysteria2_gen_credentials "$pki_dir" "$local_ip"
  else
    hysteria2_acquire_client "$name" "$remote_ip" "$pki_dir"
    [[ -f "${pki_dir}/password" ]] || cp -f "${pki_dir}/export/password" "${pki_dir}/password" 2>/dev/null || true
    [[ -f "${pki_dir}/pin.sha256" ]] || cp -f "${pki_dir}/export/pin.sha256" "${pki_dir}/pin.sha256" 2>/dev/null || true
    [[ -f "${pki_dir}/obfs.password" ]] || cp -f "${pki_dir}/export/obfs.password" "${pki_dir}/obfs.password" 2>/dev/null || true
    [[ -f "${pki_dir}/obfs.password" ]] && obfs="$(tr -d '\n' < "${pki_dir}/obfs.password")"
  fi

  hysteria2_overlay_ips "$cidr" "$mode"
  client_ip="$OPENVPN_CLIENT_IP"
  server_ip="$OPENVPN_SERVER_IP"

  hb=20
  cfg="${CONFIGS_DIR}/${name}.toml"

  if [[ "$mode" == "server" ]]; then
    hysteria2_write_server_yaml "$pki_dir" "$port" "$server_ip" "$mtu" "$dev" "$obfs"
    hysteria2_export_client_bundle "$pki_dir" "$local_ip" "$port" "$name"
    hysteria2_write_client_yaml "$pki_dir" "$port" "$local_ip" "$client_ip" "$server_ip" "$mtu" "$dev" "$obfs"
    hy_conf="${pki_dir}/server.yaml"
    ok "Wrote ${hy_conf}"
  else
    [[ -f "${pki_dir}/password" ]] || die "Missing password in ${pki_dir}"
    hysteria2_write_client_yaml "$pki_dir" "$port" "$remote_ip" "$client_ip" "$server_ip" "$mtu" "$dev" "$obfs"
    hy_conf="${pki_dir}/client.yaml"
    ok "Wrote ${hy_conf}"
    warn "Start the Hysteria2 SERVER on ${remote_ip} first."
    warn "Firewall: allow outbound UDP/${port} to server (Hetzner cloud firewall too)."
  fi

  cat > "$cfg" << EOF
# virlink — ${name}  (Hysteria2 site-to-site · QUIC)
[tunnel]
type      = "hysteria2"
mode      = "${mode}"
local_ip  = "${local_ip}"
remote_ip = "${remote_ip}"
cidr      = "${cidr}"
mtu       = ${mtu}
name      = "${name}"

[transport]
port               = ${port}
proto              = "udp"
heartbeat_interval = ${hb}

[hysteria2]
config = "${hy_conf}"
dev    = "${dev}"

[security]
encryption = true
EOF
  write_userspace_tuning "$cfg" "hysteria2"
  add_forward_section "$cfg" "$mode"
  LAST_CFG_PATH="$cfg"

  if [[ "$mode" == "server" ]]; then
    local pki="${INSTALL_DIR}/pki/${name}" hy_extra=()
    hy_extra=(
      "${pki}/password" "${pki_dir}/password" 600
      "${pki}/pin.sha256" "${pki_dir}/pin.sha256" 644
      "${pki}/client.yaml" "${pki_dir}/client.yaml" 644
    )
    [[ -f "${pki_dir}/obfs.password" ]] && hy_extra+=(
      "${pki}/obfs.password" "${pki_dir}/obfs.password" 600
    )
    virlink_server_write_manual_client "$name" "$mode" "$remote_ip" "$local_ip" "$cfg" "hysteria2" "$port" \
      "${hy_extra[@]}"
    blank
    info "Client needs ${W}password${NC} + ${W}pin.sha256${NC} from export/ or ${W}${MANUAL_CLIENT_CONF_DIR}/${remote_ip}-hysteria2-${port}.txt${NC}."
    if confirm "Push credentials to client ${remote_ip} via SSH password"; then
      openvpn_prompt_ssh
      hysteria2_push_to_client "$name" "$remote_ip" "$pki_dir" "$local_ip" "$port" \
        "$OPENVPN_SSH_USER" "$OPENVPN_SSH_PORT"
    else
      info "Copy ${pki_dir}/export/ or paste ${W}${MANUAL_CLIENT_CONF_DIR}/${remote_ip}-hysteria2-${port}.txt${NC} on client."
    fi
    hysteria2_show_fingerprint "$pki_dir"
    warn "Start SERVER first. Firewall: allow UDP/${port} (QUIC) to this host."
  fi

  blank
  local wrap_port=$((10000 + port))
  info "Overlay TUN: client ${client_ip}  ·  server ${server_ip}  (from ${cidr})"
  info "UDP wrap port: 127.0.0.1:${wrap_port}  (10000 + QUIC port ${port})"
  info "Test: ping peer overlay IP, or nc -u for UDP"
  info "Log: /var/log/virlink/${name}-hysteria2.log"
}

# ── WireGuard helpers ─────────────────────────────────────────────────────────

wireguard_overlay_addrs() {
  local cidr="$1" mode="$2"
  openvpn_overlay_ips "$cidr" "$mode"
  local ones="${cidr##*/}"
  WIREGUARD_CLIENT_IP="${OPENVPN_CLIENT_IP}"
  WIREGUARD_SERVER_IP="${OPENVPN_SERVER_IP}"
  WIREGUARD_CLIENT_ADDR="${OPENVPN_CLIENT_IP}/${ones}"
  WIREGUARD_SERVER_ADDR="${OPENVPN_SERVER_IP}/${ones}"
}

wireguard_allowed_ips() {
  local peer_ip="$1" cidr="$2"
  echo "${peer_ip}/32,${cidr}"
}

wireguard_gen_keys() {
  local dir="$1"
  mkdir -p "$dir"
  chmod 700 "$dir"
  if [[ -f "$dir/server.key" && -f "$dir/client.key" ]]; then
    ok "WireGuard keys already exist in ${dir}"
    return 0
  fi
  ensure_wireguard_deps
  info "Generating WireGuard keys (wg genkey)..."
  wg genkey | tee "$dir/server.key" | wg pubkey > "$dir/server.pub"
  wg genkey | tee "$dir/client.key" | wg pubkey > "$dir/client.pub"
  chmod 600 "$dir"/*.key 2>/dev/null || true
  chmod 644 "$dir"/*.pub 2>/dev/null || true
  ok "WireGuard keys generated"
}

wireguard_write_server_conf() {
  local pki_dir="$1" port="$2" server_addr="$3" client_pub="$4" client_ip="$5" cidr="$6"
  local server_priv
  server_priv=$(tr -d '\n' < "$pki_dir/server.key")
  cat > "${pki_dir}/wg-server.conf" << EOF
[Interface]
PrivateKey = ${server_priv}
Address = ${server_addr}
ListenPort = ${port}

[Peer]
PublicKey = $(tr -d '\n' < "$pki_dir/client.pub")
AllowedIPs = $(wireguard_allowed_ips "$client_ip" "$cidr")
EOF
}

wireguard_write_client_conf() {
  local pki_dir="$1" port="$2" endpoint_ip="$3" client_addr="$4" server_ip="$5" cidr="$6"
  local client_priv
  client_priv=$(tr -d '\n' < "$pki_dir/client.key")
  cat > "${pki_dir}/wg-client.conf" << EOF
[Interface]
PrivateKey = ${client_priv}
Address = ${client_addr}

[Peer]
PublicKey = $(tr -d '\n' < "$pki_dir/server.pub")
AllowedIPs = $(wireguard_allowed_ips "$server_ip" "$cidr")
Endpoint = ${endpoint_ip}:${port}
PersistentKeepalive = 25
EOF
}

wireguard_strip_server_secrets() {
  local dir="$1"
  rm -f "$dir/server.key" "$dir/server.pub" "$dir/wg-server.conf"
}

wireguard_show_fingerprint() {
  local pki_dir="$1"
  if [[ -f "${pki_dir}/server.pub" ]]; then
    info "Server public key: $(tr -d '\n' < "${pki_dir}/server.pub")"
  fi
  if [[ -f "${pki_dir}/client.pub" ]]; then
    info "Client public key: $(tr -d '\n' < "${pki_dir}/client.pub")"
  fi
}

wireguard_fetch_from_server() {
  local name="$1" server_host="$2" pki_dir="$3" ssh_user="$4" ssh_port="$5"
  local remote="${INSTALL_DIR}/pki/${name}"
  ensure_ssh_deps
  mkdir -p "$pki_dir"
  info "Fetching WireGuard client credentials from ${server_host}..."
  scp -P "$ssh_port" -o StrictHostKeyChecking=accept-new \
    "${ssh_user}@${server_host}:${remote}/client.key" \
    "${ssh_user}@${server_host}:${remote}/client.pub" \
    "${ssh_user}@${server_host}:${remote}/server.pub" \
    "${ssh_user}@${server_host}:${remote}/wg-client.conf" \
    "$pki_dir/" || die "SCP failed — check SSH access to ${server_host}"
  wireguard_strip_server_secrets "$pki_dir"
  ok "WireGuard credentials fetched from ${server_host}"
}

wireguard_acquire_client_pki() {
  local name="$1" server_host="$2" pki_dir="$3"
  if [[ -f "${pki_dir}/client.key" && -f "${pki_dir}/server.pub" && -f "${pki_dir}/wg-client.conf" ]]; then
    ok "WireGuard client credentials present"
    return 0
  fi
  blank
  info "Client needs: client.key, server.pub, wg-client.conf from the server."
  if confirm "Fetch from server ${server_host} via SSH?"; then
    openvpn_prompt_ssh
    wireguard_fetch_from_server "$name" "$server_host" "$pki_dir" \
      "$OPENVPN_SSH_USER" "$OPENVPN_SSH_PORT"
    return 0
  fi
  die "Missing WireGuard credentials in ${pki_dir} — copy from server or use SSH fetch"
}

wireguard_push_to_client() {
  local name="$1" client_host="$2" pki_dir="$3" ssh_user="$4" ssh_port="$5"
  ensure_ssh_deps
  local remote="${INSTALL_DIR}/pki/${name}"
  info "Pushing WireGuard client credentials to ${client_host}..."
  ssh -p "$ssh_port" -o StrictHostKeyChecking=accept-new \
    "${ssh_user}@${client_host}" "mkdir -p '${remote}' && chmod 700 '${remote}'"
  scp -P "$ssh_port" -o StrictHostKeyChecking=accept-new \
    "${pki_dir}/client.key" \
    "${pki_dir}/client.pub" \
    "${pki_dir}/server.pub" \
    "${pki_dir}/wg-client.conf" \
    "${ssh_user}@${client_host}:${remote}/" || die "SCP push failed"
  ok "WireGuard credentials pushed to ${client_host}:${remote}"
}

gen_wireguard() {
  local name mode local_ip remote_ip cidr port mtu dev pki_dir wg_conf cfg hb
  local client_ip server_ip client_addr server_addr
  collect_base_inputs name mode local_ip remote_ip cidr
  blank
  info "WireGuard site-to-site — kernel crypto, UDP transport."
  prompt port "WireGuard UDP port" "51820"
  prompt mtu "Overlay MTU" "1420"
  dev="wg-virlink0"

  ensure_wireguard_deps
  ensure_wireguard_module
  pki_dir="${INSTALL_DIR}/pki/${name}"
  mkdir -p "$pki_dir"

  if [[ "$mode" == "server" ]]; then
    wireguard_gen_keys "$pki_dir"
  else
    wireguard_acquire_client_pki "$name" "$remote_ip" "$pki_dir"
  fi

  wireguard_overlay_addrs "$cidr" "$mode"
  client_ip="$WIREGUARD_CLIENT_IP"
  server_ip="$WIREGUARD_SERVER_IP"
  client_addr="$WIREGUARD_CLIENT_ADDR"
  server_addr="$WIREGUARD_SERVER_ADDR"

  hb=20

  if [[ "$mode" == "server" ]]; then
    wireguard_write_server_conf "$pki_dir" "$port" "$server_addr" "" "$client_ip" "$cidr"
    wireguard_write_client_conf "$pki_dir" "$port" "$local_ip" "$client_addr" "$server_ip" "$cidr"
    wireguard_allow_firewall_port "$port"
    wg_conf="${pki_dir}/wg-server.conf"
    ok "Wrote ${wg_conf}"
  else
    wireguard_write_client_conf "$pki_dir" "$port" "$remote_ip" "$client_addr" "$server_ip" "$cidr"
    wg_conf="${pki_dir}/wg-client.conf"
    ok "Wrote ${wg_conf}  Endpoint=${remote_ip}:${port}"
    blank
    warn "Start the WireGuard SERVER on ${remote_ip} first."
    warn "Firewall: allow UDP/${port} to server (cloud firewall too)."
  fi

  cfg="${CONFIGS_DIR}/${name}.toml"
  cat > "$cfg" << EOF
# virlink — ${name}  (WireGuard site-to-site · UDP)
[tunnel]
type      = "wireguard"
mode      = "${mode}"
local_ip  = "${local_ip}"
remote_ip = "${remote_ip}"
cidr      = "${cidr}"
mtu       = ${mtu}
name      = "${name}"

[transport]
port               = ${port}
proto              = "udp"
heartbeat_interval = ${hb}

[wireguard]
config = "${wg_conf}"
dev    = "${dev}"

[security]
encryption = true
EOF
  write_openvpn_tuning "$cfg" "fast"
  add_forward_section "$cfg" "$mode"
  LAST_CFG_PATH="$cfg"

  if [[ "$mode" == "server" ]]; then
    local pki="${INSTALL_DIR}/pki/${name}"
    virlink_server_write_manual_client "$name" "$mode" "$remote_ip" "$local_ip" "$cfg" "wireguard" "$port" \
      "${pki}/client.key" "${pki_dir}/client.key" 600 \
      "${pki}/client.pub" "${pki_dir}/client.pub" 644 \
      "${pki}/server.pub" "${pki_dir}/server.pub" 644 \
      "${pki}/wg-client.conf" "${pki_dir}/wg-client.conf" 644
    blank
    info "Privacy: server private key stays on this host only."
    info "Client install: ${W}${MANUAL_CLIENT_CONF_DIR}/${remote_ip}-wireguard-${port}.txt${NC}"
    if confirm "Push credentials to client ${remote_ip} via SSH"; then
      openvpn_prompt_ssh
      wireguard_push_to_client "$name" "$remote_ip" "$pki_dir" \
        "$OPENVPN_SSH_USER" "$OPENVPN_SSH_PORT"
    else
      info "Copy ${pki_dir}/ or paste ${W}${MANUAL_CLIENT_CONF_DIR}/${remote_ip}-wireguard-${port}.txt${NC} on client."
    fi
    wireguard_show_fingerprint "$pki_dir"
    blank
    warn "Start this server tunnel before the client: virlink-setup → Start tunnel → ${name}"
    warn "Firewall: allow UDP/${port} from client ${remote_ip}"
  fi

  blank
  warn "Firewall: allow UDP/${port} between ${local_ip} and ${remote_ip}"
  if [[ "$mode" == "server" ]]; then
    info "Client overlay: ${client_addr}  ·  Server overlay: ${server_addr}"
  fi
  info "Test: ping peer overlay IP after both sides are up"
}

# ── IKEv2 / strongSwan helpers ────────────────────────────────────────────────

_ikev2_pkg_names() {
  case "$(_detect_pkg_mgr)" in
    dnf|yum|zypper) echo strongswan strongswan-swanctl ;;
    pacman)         echo strongswan ;;
    apk)            echo strongswan swanctl ;;
    *)              echo strongswan strongswan-swanctl strongswan-charon ;;
  esac
}

ensure_ikev2_deps() {
  local -a need=() pkg
  for c in swanctl ip; do
    command -v "$c" &>/dev/null || need+=("shell")
  done
  if command -v swanctl &>/dev/null && command -v ip &>/dev/null; then
    ok "IKEv2 ready (strongSwan swanctl)"
    systemctl enable strongswan 2>/dev/null || systemctl enable strongswan-starter 2>/dev/null || true
    return 0
  fi
  require_root
  warn "strongSwan missing — installing..."
  for pkg in $(_ikev2_pkg_names); do
    _pkg_install "$pkg" 2>/dev/null && break
  done
  command -v swanctl &>/dev/null || die "swanctl not found after install"
  ok "strongSwan installed"
}

ikev2_allow_firewall() {
  wireguard_allow_firewall_port 500
  wireguard_allow_firewall_port 4500
}

ikev2_default_if_id() {
  local name="$1" h=0 i c
  for ((i=0; i<${#name}; i++)); do
    c=$(printf '%d' "'${name:$i:1}")
    h=$(( (h * 31 + c) % 60000 + 1 ))
  done
  (( h < 2 )) && h=42
  echo "$h"
}

ikev2_gen_pki() {
  local dir="$1"
  mkdir -p "$dir"
  chmod 700 "$dir"
  if [[ -f "$dir/ca.crt" && -f "$dir/server.crt" && -f "$dir/client.crt" ]]; then
    ok "IKEv2 PKI already exists in ${dir}"
    return 0
  fi
  info "Generating IKEv2 PKI (ECDSA P-256, CA + server + client)..."
  openvpn_openssl_extfile "$dir"
  openssl ecparam -genkey -name prime256v1 -out "$dir/ca.key" \
    || die "OpenSSL: cannot generate CA key"
  openvpn_create_ca_cert "$dir"
  openssl ecparam -genkey -name prime256v1 -out "$dir/server.key" \
    || die "OpenSSL: cannot generate server key"
  openvpn_sign_server_cert "$dir"
  openssl ecparam -genkey -name prime256v1 -out "$dir/client.key" \
    || die "OpenSSL: cannot generate client key"
  openvpn_sign_client_cert "$dir"
  rm -f "$dir/server.csr" "$dir/client.csr"
  chmod 600 "$dir"/*.key 2>/dev/null || true
  chmod 644 "$dir"/*.crt 2>/dev/null || true
  ok "IKEv2 PKI generated"
}

ikev2_install_swanctl_layout() {
  local pki_dir="$1" mode="$2"
  local swanctl="${pki_dir}/swanctl"
  mkdir -p "${swanctl}/conf.d" "${swanctl}/x509ca" "${swanctl}/x509" "${swanctl}/private"
  cp -f "${pki_dir}/ca.crt" "${swanctl}/x509ca/"
  if [[ "$mode" == "server" ]]; then
    cp -f "${pki_dir}/server.crt" "${swanctl}/x509/"
    cp -f "${pki_dir}/server.key" "${swanctl}/private/"
    rm -f "${swanctl}/private/client.key" "${swanctl}/x509/client.crt"
  else
    cp -f "${pki_dir}/client.crt" "${swanctl}/x509/"
    cp -f "${pki_dir}/client.key" "${swanctl}/private/"
    rm -f "${swanctl}/private/server.key" "${swanctl}/x509/server.crt"
  fi
  chmod 600 "${swanctl}/private/"* 2>/dev/null || true
  chmod 644 "${swanctl}/x509/"* "${swanctl}/x509ca/"* 2>/dev/null || true
}

ikev2_write_swanctl_conf() {
  local mode="$1" local_ip="$2" remote_ip="$3" cidr="$4" if_id="$5" swanctl_dir="$6"
  local start_action local_cert remote_id local_id
  if [[ "$mode" == "server" ]]; then
    start_action="trap"
    local_cert="server.crt"
    local_id="$local_ip"
    remote_id="$remote_ip"
  else
    start_action="start"
    local_cert="client.crt"
    local_id="$local_ip"
    remote_id="$remote_ip"
  fi
  cat > "${swanctl_dir}/conf.d/virlink.conf" << EOF
connections {
  virlink {
    version = 2
    mobike = no
    reauth_time = 0

    local_addrs = ${local_ip}
    remote_addrs = ${remote_ip}

    local {
      auth = pubkey
      certs = ${local_cert}
      id = ${local_id}
    }
    remote {
      auth = pubkey
      id = ${remote_id}
    }

    children {
      net {
        local_ts = ${cidr}
        remote_ts = ${cidr}
        esp_proposals = aes256gcm-modp2048,aes128gcm-modp2048,aes256-sha256-modp2048
        start_action = ${start_action}
        close_action = restart
        dpd_action = restart
        if_id_in = ${if_id}
        if_id_out = ${if_id}
      }
    }
  }
}
EOF
}

ikev2_build_client_swanctl() {
  local pki_dir="$1" server_ip="$2" client_ip="$3" cidr="$4" if_id="$5"
  local target="${pki_dir}/swanctl-client"
  mkdir -p "${target}/conf.d" "${target}/x509ca" "${target}/x509" "${target}/private"
  cp -f "${pki_dir}/ca.crt" "${target}/x509ca/"
  cp -f "${pki_dir}/client.crt" "${target}/x509/"
  cp -f "${pki_dir}/client.key" "${target}/private/"
  chmod 600 "${target}/private/client.key"
  ikev2_write_swanctl_conf client "$client_ip" "$server_ip" "$cidr" "$if_id" "$target"
}

ikev2_strip_server_secrets() {
  local dir="$1"
  rm -f "$dir/ca.key" "$dir/server.key" "$dir/server.crt"
  rm -f "$dir/swanctl/private/server.key" "$dir/swanctl/x509/server.crt" 2>/dev/null || true
}

ikev2_fetch_from_server() {
  local name="$1" server_host="$2" pki_dir="$3" ssh_user="$4" ssh_port="$5"
  local remote="${INSTALL_DIR}/pki/${name}"
  ensure_ssh_deps
  mkdir -p "$pki_dir"
  info "Fetching IKEv2 client credentials from ${server_host}..."
  scp -P "$ssh_port" -o StrictHostKeyChecking=accept-new -r \
    "${ssh_user}@${server_host}:${remote}/swanctl-client" \
    "${pki_dir}/swanctl" 2>/dev/null || \
  scp -P "$ssh_port" -o StrictHostKeyChecking=accept-new -r \
    "${ssh_user}@${server_host}:${remote}/swanctl" \
    "$pki_dir/" || die "SCP failed — check SSH access to ${server_host}"
  ikev2_strip_server_secrets "$pki_dir"
  ok "IKEv2 swanctl fetched from ${server_host}"
}

ikev2_acquire_client_pki() {
  local name="$1" server_host="$2" pki_dir="$3"
  if [[ -d "${pki_dir}/swanctl/conf.d" && -f "${pki_dir}/swanctl/x509ca/ca.crt" ]]; then
    ok "IKEv2 client swanctl present"
    return 0
  fi
  blank
  info "Client needs swanctl/ tree from the server (CA + client cert/key + conf)."
  if confirm "Fetch from server ${server_host} via SSH?"; then
    openvpn_prompt_ssh
    ikev2_fetch_from_server "$name" "$server_host" "$pki_dir" \
      "$OPENVPN_SSH_USER" "$OPENVPN_SSH_PORT"
    return 0
  fi
  die "Missing IKEv2 swanctl in ${pki_dir} — copy from server or use SSH fetch"
}

ikev2_push_to_client() {
  local name="$1" client_host="$2" pki_dir="$3" ssh_user="$4" ssh_port="$5"
  ensure_ssh_deps
  local remote="${INSTALL_DIR}/pki/${name}"
  local src="${pki_dir}/swanctl-client"
  [[ -d "$src" ]] || src="${pki_dir}/swanctl"
  info "Pushing IKEv2 client swanctl to ${client_host}..."
  ssh -p "$ssh_port" -o StrictHostKeyChecking=accept-new \
    "${ssh_user}@${client_host}" "mkdir -p '${remote}' && chmod 700 '${remote}'"
  scp -P "$ssh_port" -o StrictHostKeyChecking=accept-new -r \
    "${src}" "${ssh_user}@${client_host}:${remote}/swanctl" || die "SCP push failed"
  ok "IKEv2 swanctl pushed to ${client_host}:${remote}/swanctl"
}

gen_ikev2() {
  local name mode local_ip remote_ip cidr mtu dev pki_dir swanctl_dir cfg hb if_id port
  collect_base_inputs name mode local_ip remote_ip cidr
  blank
  info "IKEv2 site-to-site — strongSwan kernel IPsec (multi-core ESP, single overlay IP)."
  prompt mtu "Overlay MTU" "1400"
  dev="ipsec0"
  port=500

  ensure_ikev2_deps
  pki_dir="${INSTALL_DIR}/pki/${name}"
  mkdir -p "$pki_dir"

  if [[ "$mode" == "server" ]]; then
    ikev2_gen_pki "$pki_dir"
  else
    ikev2_acquire_client_pki "$name" "$remote_ip" "$pki_dir"
  fi

  if_id="$(ikev2_default_if_id "$name")"
  swanctl_dir="${pki_dir}/swanctl"

  if [[ "$mode" == "server" ]]; then
    ikev2_install_swanctl_layout "$pki_dir" server
    ikev2_write_swanctl_conf server "$local_ip" "$remote_ip" "$cidr" "$if_id" "$swanctl_dir"
    ikev2_build_client_swanctl "$pki_dir" "$local_ip" "$remote_ip" "$cidr" "$if_id"
    ikev2_allow_firewall
    ok "Wrote ${swanctl_dir}/conf.d/virlink.conf  if_id=${if_id}"
  else
    [[ -d "$swanctl_dir" ]] || die "Missing ${swanctl_dir}"
    ikev2_install_swanctl_layout "$pki_dir" client
    ikev2_write_swanctl_conf client "$local_ip" "$remote_ip" "$cidr" "$if_id" "$swanctl_dir"
    ok "Wrote ${swanctl_dir}/conf.d/virlink.conf  if_id=${if_id}"
    blank
    warn "Start the IKEv2 SERVER on ${remote_ip} first."
    warn "Firewall: allow UDP 500 and 4500 to server (cloud firewall too)."
  fi

  hb=20
  cfg="${CONFIGS_DIR}/${name}.toml"
  cat > "$cfg" << EOF
# virlink — ${name}  (IKEv2 / strongSwan site-to-site)
[tunnel]
type      = "ikev2"
mode      = "${mode}"
local_ip  = "${local_ip}"
remote_ip = "${remote_ip}"
cidr      = "${cidr}"
mtu       = ${mtu}
name      = "${name}"

[transport]
port               = ${port}
proto              = "udp"
heartbeat_interval = ${hb}

[ikev2]
swanctl_dir = "${swanctl_dir}"
dev         = "${dev}"
conn        = "virlink"
child       = "net"
if_id       = ${if_id}

[security]
encryption = true
EOF
  write_openvpn_tuning "$cfg" "fast"
  add_forward_section "$cfg" "$mode"
  LAST_CFG_PATH="$cfg"

  if [[ "$mode" == "server" ]]; then
    blank
    info "Privacy: CA/server private keys stay on this host only."
    info "Client needs: ${pki_dir}/swanctl/ (client cert layout) — use push or manual copy."
    if confirm "Push client swanctl to ${remote_ip} via SSH"; then
      openvpn_prompt_ssh
      ikev2_push_to_client "$name" "$remote_ip" "$pki_dir" \
        "$OPENVPN_SSH_USER" "$OPENVPN_SSH_PORT"
    fi
    blank
    warn "Start this server tunnel before the client: virlink-setup → Start tunnel → ${name}"
    warn "Firewall: allow UDP 500/4500 from client ${remote_ip}"
  fi

  blank
  warn "Firewall: allow UDP 500 and 4500 between ${local_ip} and ${remote_ip}"
  info "Test: ping peer overlay IP after IKE SA is up (swanctl --list-sas)"
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
  virlink_server_write_manual_client "$name" "$mode" "$remote_ip" "$local_ip" "$cfg" "tcp" "$port"
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
  virlink_server_write_manual_client "$name" "$mode" "$remote_ip" "$local_ip" "$cfg" "udp" "$port"
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
  virlink_server_write_manual_client "$name" "$mode" "$remote_ip" "$local_ip" "$cfg" "icmp" "0"
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
  virlink_server_write_manual_client "$name" "$mode" "$remote_ip" "$local_ip" "$cfg" "bip" "0"
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
    if confirm "Update core and setup script to ${LATEST_TAG}"; then
      do_update_core
      return
    fi
  else
    ok "Core is already up to date."
    if confirm "Sync setup script from latest release anyway"; then
      do_update_core
      return
    fi
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
