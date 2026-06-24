#!/usr/bin/env bash
# virlink — interactive setup & management
# https://github.com/hosseinpv1379/virtlink
set -euo pipefail

# ── release info ──────────────────────────────────────────────────────────────
GITHUB_REPO="hosseinpv1379/virtlink"
RELEASE_BASE="https://github.com/${GITHUB_REPO}/releases/latest/download"
INSTALL_DIR="/opt/virlink"
VERSION="2.0.0"

VIRLINK_BIN="${INSTALL_DIR}/virlink"
CONFIGS_DIR="${INSTALL_DIR}/configs"
PIDS_DIR="/var/run/virlink"
LOGS_DIR="/var/log/virlink"

# ── colors ────────────────────────────────────────────────────────────────────
R='\033[0;31m' G='\033[0;32m' Y='\033[0;33m'
B='\033[0;34m' C='\033[0;36m' W='\033[1;37m'
DIM='\033[2m' BOLD='\033[1m' NC='\033[0m'

# ── helpers ───────────────────────────────────────────────────────────────────
info()  { echo -e "  ${C}→${NC} $*"; }
ok()    { echo -e "  ${G}✓${NC} $*"; }
warn()  { echo -e "  ${Y}⚠${NC} $*"; }
err()   { echo -e "  ${R}✗${NC} $*" >&2; }
die()   { err "$*"; exit 1; }
sep()   { echo -e "${DIM}────────────────────────────────────────────────${NC}"; }
blank() { echo; }

header() {
  clear 2>/dev/null || true
  echo -e "${BOLD}${B}"
  echo "  ██╗   ██╗██╗██████╗ ██╗     ██╗███╗   ██╗██╗  ██╗"
  echo "  ██║   ██║██║██╔══██╗██║     ██║████╗  ██║██║ ██╔╝"
  echo "  ██║   ██║██║██████╔╝██║     ██║██╔██╗ ██║█████╔╝ "
  echo "  ╚██╗ ██╔╝██║██╔══██╗██║     ██║██║╚██╗██║██╔═██╗ "
  echo "   ╚████╔╝ ██║██║  ██║███████╗██║██║ ╚████║██║  ██╗"
  echo "    ╚═══╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝"
  echo -e "${NC}  ${DIM}Kernel Tunnel Manager  v${VERSION}${NC}"
  blank
}

# All prompts go to /dev/tty so they work even inside subshells
tty_ask() {
  printf "  ${W}?${NC} %s: " "$1" >> /dev/tty
}

prompt() {
  local _var="$1" _msg="$2" _def="${3:-}" _val
  if [[ -n "$_def" ]]; then
    printf "  ${W}?${NC} %s ${DIM}[%s]${NC}: " "$_msg" "$_def" >> /dev/tty
  else
    printf "  ${W}?${NC} %s: " "$_msg" >> /dev/tty
  fi
  read -r _val < /dev/tty
  [[ -z "$_val" ]] && _val="$_def"
  printf -v "$_var" '%s' "$_val"
}

confirm() {
  local _ans
  printf "  ${W}?${NC} %s [y/N]: " "$1" >> /dev/tty
  read -r _ans < /dev/tty
  [[ "${_ans,,}" == "y" ]]
}

pick() {
  local _var="$1"; shift
  local _title="$1"; shift
  local _opts=("$@") _n
  blank
  echo -e "  ${W}${_title}${NC}"
  sep
  for i in "${!_opts[@]}"; do
    printf "    ${C}%2d${NC}  %s\n" $((i+1)) "${_opts[$i]}"
  done
  blank
  while true; do
    printf "  ${W}?${NC} Choose [1-${#_opts[@]}]: " >> /dev/tty
    read -r _n < /dev/tty
    if [[ "$_n" =~ ^[0-9]+$ ]] && (( _n >= 1 && _n <= ${#_opts[@]} )); then
      printf -v "$_var" '%s' "${_opts[$((_n-1))]}"
      return
    fi
    warn "Invalid choice, try again."
  done
}

require_root() {
  [[ $EUID -eq 0 ]] || die "This action requires root. Run: sudo bash $0"
}

ensure_dirs() {
  mkdir -p "$CONFIGS_DIR" "$PIDS_DIR" "$LOGS_DIR"
}

# ── auto install / self-update ────────────────────────────────────────────────
do_install() {
  require_root
  header
  echo -e "  ${BOLD}Installing virlink to ${INSTALL_DIR}${NC}"
  sep
  blank

  info "Creating directories..."
  mkdir -p "$INSTALL_DIR" "$CONFIGS_DIR" "$PIDS_DIR" "$LOGS_DIR"

  info "Downloading virlink binary..."
  if command -v curl &>/dev/null; then
    curl -fsSL "${RELEASE_BASE}/virlink" -o "${VIRLINK_BIN}.tmp"
  elif command -v wget &>/dev/null; then
    wget -q "${RELEASE_BASE}/virlink" -O "${VIRLINK_BIN}.tmp"
  else
    die "curl or wget is required for installation."
  fi
  chmod +x "${VIRLINK_BIN}.tmp"
  mv "${VIRLINK_BIN}.tmp" "$VIRLINK_BIN"
  ok "Binary: $VIRLINK_BIN"

  info "Downloading setup.sh..."
  if command -v curl &>/dev/null; then
    curl -fsSL "${RELEASE_BASE}/setup.sh" -o "${INSTALL_DIR}/setup.sh.tmp"
  else
    wget -q "${RELEASE_BASE}/setup.sh" -O "${INSTALL_DIR}/setup.sh.tmp"
  fi
  chmod +x "${INSTALL_DIR}/setup.sh.tmp"
  mv "${INSTALL_DIR}/setup.sh.tmp" "${INSTALL_DIR}/setup.sh"
  ok "Script: ${INSTALL_DIR}/setup.sh"

  # symlinks for easy access from anywhere
  ln -sf "${INSTALL_DIR}/setup.sh" /usr/local/bin/virlink-setup 2>/dev/null || true
  ln -sf "$VIRLINK_BIN" /usr/local/bin/virlink 2>/dev/null || true

  blank
  ok "Installation complete!"
  ok "Run anytime: virlink-setup"
  blank
  info "Launching setup..."
  blank
  exec bash "${INSTALL_DIR}/setup.sh" "${@:-menu}"
}

# detect if running via curl pipe (not installed)
_this="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || realpath "${BASH_SOURCE[0]}" 2>/dev/null || echo "$0")"
if [[ "$_this" != "${INSTALL_DIR}/setup.sh" ]] || [[ ! -x "$VIRLINK_BIN" ]]; then
  do_install "$@"
  exit 0
fi

# ── tunnel process management ─────────────────────────────────────────────────
pid_file()  { echo "${PIDS_DIR}/$1.pid"; }
log_file()  { echo "${LOGS_DIR}/$1.log"; }

is_running() {
  local _pf; _pf="$(pid_file "$1")"
  [[ -f "$_pf" ]] && kill -0 "$(cat "$_pf")" 2>/dev/null
}

tunnel_start() {
  local name="$1" cfg log pf
  cfg="${CONFIGS_DIR}/${name}.toml"
  [[ -f "$cfg" ]] || die "Config not found: $cfg"
  if is_running "$name"; then
    warn "Tunnel '$name' already running (PID $(cat "$(pid_file "$name")"))"
    return
  fi
  log="$(log_file "$name")"
  pf="$(pid_file "$name")"
  info "Starting '$name'..."
  nohup "$VIRLINK_BIN" -c "$cfg" >> "$log" 2>&1 &
  echo $! > "$pf"
  disown $!
  sleep 1
  if is_running "$name"; then
    ok "Tunnel '$name' running (PID $(cat "$pf"))"
    ok "Log: $log"
  else
    err "Failed to start. Check: $log"
    tail -20 "$log" 2>/dev/null || true
  fi
}

tunnel_stop() {
  local name="$1" pid
  if ! is_running "$name"; then warn "Tunnel '$name' not running."; return; fi
  pid="$(cat "$(pid_file "$name")")"
  info "Stopping '$name' (PID $pid)..."
  kill -TERM "$pid" 2>/dev/null || true
  sleep 2
  kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null || true
  rm -f "$(pid_file "$name")"
  ok "Stopped."
}

tunnel_status() {
  local name="$1" cfg
  cfg="${CONFIGS_DIR}/${name}.toml"
  blank
  echo -e "  ${BOLD}Tunnel: ${C}${name}${NC}"
  sep
  if is_running "$name"; then
    echo -e "  Status : ${G}RUNNING${NC} (PID $(cat "$(pid_file "$name")"))"
  else
    echo -e "  Status : ${R}STOPPED${NC}"
  fi
  if [[ -f "$cfg" ]]; then
    echo -e "  Config : $cfg"
    local t m li ri
    t=$(grep 'type '     "$cfg" 2>/dev/null | head -1 | awk -F'"' '{print $2}')
    m=$(grep 'mode '     "$cfg" 2>/dev/null | head -1 | awk -F'"' '{print $2}')
    li=$(grep 'local_ip' "$cfg" 2>/dev/null | awk -F'"' '{print $2}')
    ri=$(grep 'remote_ip' "$cfg" 2>/dev/null | awk -F'"' '{print $2}')
    echo -e "  Type   : ${Y}${t}${NC}  (${m})"
    echo -e "  Local  : ${li}"
    echo -e "  Remote : ${ri}"
  fi
  if [[ -f "$(log_file "$name")" ]]; then
    blank; echo -e "  ${DIM}Last 10 log lines:${NC}"
    tail -10 "$(log_file "$name")" | sed 's/^/    /'
  fi
  blank
}

list_tunnels() {
  local cfgs=("${CONFIGS_DIR}"/*.toml)
  if [[ ! -f "${cfgs[0]}" ]]; then warn "No tunnels configured yet."; return 1; fi
  blank
  printf "  ${BOLD}%-24s %-16s %-10s %s${NC}\n" "NAME" "TYPE" "STATUS" "REMOTE"
  sep
  for cfg in "${cfgs[@]}"; do
    local name t r st
    name=$(basename "$cfg" .toml)
    t=$(grep 'type '     "$cfg" 2>/dev/null | head -1 | awk -F'"' '{print $2}')
    r=$(grep 'remote_ip' "$cfg" 2>/dev/null | awk -F'"' '{print $2}')
    if is_running "$name"; then st="${G}running${NC}"; else st="${R}stopped${NC}"; fi
    printf "  %-24s %-16s " "$name" "$t"
    echo -e "${st}  ${r}"
  done
  blank
}

install_systemd() {
  local name="$1" cfg svc
  cfg="${CONFIGS_DIR}/${name}.toml"
  [[ -f "$cfg" ]] || die "Config not found: $cfg"
  svc="/etc/systemd/system/virlink@${name}.service"
  cat > "$svc" <<EOF
[Unit]
Description=virlink tunnel — ${name}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${VIRLINK_BIN} -c ${cfg}
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "virlink@${name}"
  ok "Service installed: virlink@${name}"
  ok "Start: systemctl start virlink@${name}"
}

# ── config helpers ────────────────────────────────────────────────────────────
# NOTE: these functions write to LAST_CFG_PATH (global) instead of echoing,
# so they can be called directly (not inside $(...)) — avoids subshell stdin bug

LAST_CFG_PATH=""

write_transport() {
  local f="$1" port="$2" proto="$3"
  cat >> "$f" <<EOF

[transport]
port               = ${port}
proto              = "${proto}"
heartbeat_interval = 10

[tuning]
bbr          = true
multipath    = false
channel_size = 10_000

[logging]
level = "info"
EOF
}

write_forward_block() {
  local f="$1" mode="$2"
  [[ "$mode" != "client" ]] && return
  cat >> "$f" <<'EOF'

# ── port forwarding (client only) ─────────────────────────────────────────────
[forward]
enabled = false
rules   = [
  # "1000:2000",    # :1000  →  peer:2000  (tcp+udp)
  # "8080:80/tcp",
]
EOF
}

collect_base() {
  # sets globals: _name _mode _local _remote _cidr
  blank
  prompt _name   "Tunnel name (e.g. iran-kh)" ""
  [[ -z "$_name" ]] && die "Name cannot be empty."
  _name="${_name// /-}"
  pick _mode "Mode" "client" "server"
  blank
  prompt _local  "This server public IP"  ""
  prompt _remote "Peer server public IP"  ""
  prompt _cidr   "Overlay subnet (CIDR)"  "10.20.10.0/24"
}

gen_gre_fou() {
  local _name _mode _local _remote _cidr _port _mtu _cfg
  collect_base
  prompt _port "FOU UDP port" "5556"
  prompt _mtu  "MTU"          "1420"
  _cfg="${CONFIGS_DIR}/${_name}.toml"
  cat > "$_cfg" <<EOF
# virlink — ${_name}  (generated by setup.sh)
[tunnel]
type      = "gre-fou"
mode      = "${_mode}"
local_ip  = "${_local}"
remote_ip = "${_remote}"
cidr      = "${_cidr}"
mtu       = ${_mtu}
EOF
  write_transport "$_cfg" "$_port" "fou"
  write_forward_block "$_cfg" "$_mode"
  LAST_CFG_PATH="$_cfg"
}

gen_ipip_fou() {
  local _name _mode _local _remote _cidr _port _mtu _cfg
  collect_base
  prompt _port "FOU UDP port" "5055"
  prompt _mtu  "MTU"          "1440"
  _cfg="${CONFIGS_DIR}/${_name}.toml"
  cat > "$_cfg" <<EOF
# virlink — ${_name}
[tunnel]
type      = "ipip-fou"
mode      = "${_mode}"
local_ip  = "${_local}"
remote_ip = "${_remote}"
cidr      = "${_cidr}"
mtu       = ${_mtu}
EOF
  write_transport "$_cfg" "$_port" "fou"
  write_forward_block "$_cfg" "$_mode"
  LAST_CFG_PATH="$_cfg"
}

gen_bonded() {
  local _name _mode _local _remote _cidr _p1 _p2 _mtu _cfg
  collect_base
  prompt _p1  "Path-1 FOU port" "5557"
  prompt _p2  "Path-2 FOU port" "5558"
  prompt _mtu "MTU"             "1400"
  _cfg="${CONFIGS_DIR}/${_name}.toml"
  cat > "$_cfg" <<EOF
# virlink — ${_name}
[tunnel]
type      = "bonded-gre-fou"
mode      = "${_mode}"
local_ip  = "${_local}"
remote_ip = "${_remote}"
cidr      = "${_cidr}"
mtu       = ${_mtu}

[transport]
port               = ${_p1}
port2              = ${_p2}
proto              = "fou"
heartbeat_interval = 10

[tuning]
bbr          = true
multipath    = true
channel_size = 10_000

[logging]
level = "info"
EOF
  write_forward_block "$_cfg" "$_mode"
  LAST_CFG_PATH="$_cfg"
}

gen_l2tpv3() {
  local _name _mode _local _remote _cidr _port _mtu _cfg
  collect_base
  prompt _port "UDP port" "5059"
  prompt _mtu  "MTU"      "1464"
  _cfg="${CONFIGS_DIR}/${_name}.toml"
  cat > "$_cfg" <<EOF
# virlink — ${_name}
[tunnel]
type      = "l2tpv3"
mode      = "${_mode}"
local_ip  = "${_local}"
remote_ip = "${_remote}"
cidr      = "${_cidr}"
mtu       = ${_mtu}

[transport]
port               = ${_port}
proto              = "l2tp"
heartbeat_interval = 10

[l2tp]
client_tunnel_id  = 1000
server_tunnel_id  = 2000
client_session_id = 1000
server_session_id = 2000

[tuning]
bbr          = true
channel_size = 10_000

[logging]
level = "info"
EOF
  write_forward_block "$_cfg" "$_mode"
  LAST_CFG_PATH="$_cfg"
}

gen_gre_wg() {
  local _name _mode _local _remote _cidr _port _mtu _cfg
  local _cpriv _cpub _spriv _spub
  collect_base
  prompt _port "WireGuard port" "51820"
  prompt _mtu  "MTU"            "1380"
  blank
  warn "Generate WireGuard keys first: run option 4 from the main menu."
  warn "Or press Enter to fill in keys later."
  prompt _cpriv "Client private key" ""
  prompt _cpub  "Client public key"  ""
  prompt _spriv "Server private key" ""
  prompt _spub  "Server public key"  ""
  _cfg="${CONFIGS_DIR}/${_name}.toml"
  cat > "$_cfg" <<EOF
# virlink — ${_name}
[tunnel]
type      = "gre-wg"
mode      = "${_mode}"
local_ip  = "${_local}"
remote_ip = "${_remote}"
cidr      = "${_cidr}"
mtu       = ${_mtu}

[transport]
port               = ${_port}
proto              = "wireguard"
heartbeat_interval = 10

[wireguard]
client_private_key = "${_cpriv}"
client_public_key  = "${_cpub}"
server_private_key = "${_spriv}"
server_public_key  = "${_spub}"

[security]
encryption = true

[tuning]
bbr          = true
channel_size = 10_000

[logging]
level = "info"
EOF
  write_forward_block "$_cfg" "$_mode"
  LAST_CFG_PATH="$_cfg"
}

gen_udp_obfs() {
  local _name _mode _local _remote _cidr _port _mtu _key _maskval _mask _pad _cfg
  collect_base
  prompt _port "UDP port (443 recommended for Iran)" "443"
  prompt _mtu  "MTU"                                 "1400"
  blank
  echo -e "  ${W}Obfuscation settings${NC}"; sep
  prompt _key "Shared secret key (same on both servers)" ""
  [[ -z "$_key" ]] && die "Key cannot be empty."
  pick _maskval "Traffic mask (what it looks like to DPI)" \
    "noise  — random ciphertext, no protocol header" \
    "quic   — fake QUIC v1 header on port 443  (recommended for Iran)" \
    "dtls   — fake DTLS 1.2 header  (WebRTC-like)"
  _mask="${_maskval%% *}"
  if confirm "Enable random padding (defeats length analysis)"; then
    _pad="true"
  else
    _pad="false"
  fi
  _cfg="${CONFIGS_DIR}/${_name}.toml"
  cat > "$_cfg" <<EOF
# virlink — ${_name}
[tunnel]
type      = "udp-obfs"
mode      = "${_mode}"
local_ip  = "${_local}"
remote_ip = "${_remote}"
cidr      = "${_cidr}"
mtu       = ${_mtu}

[transport]
port               = ${_port}
proto              = "udp-obfs"
heartbeat_interval = 10

[obfs]
key     = "${_key}"
mask    = "${_mask}"
padding = ${_pad}

[security]
encryption = true

[tuning]
bbr          = true
channel_size = 10_000

[logging]
level = "info"
EOF
  write_forward_block "$_cfg" "$_mode"
  LAST_CFG_PATH="$_cfg"
}

gen_ipsec() {
  local _name _mode _local _remote _cidr _port _mtu _cfg
  local _spout _spin _eout _ein _aout _ain
  collect_base
  prompt _port "FOU port" "5556"
  prompt _mtu  "MTU"      "1380"
  blank
  warn "Generate random IPsec keys:"
  warn "  python3 -c \"import os; print('0x'+os.urandom(32).hex())\""
  blank
  local _rand1 _rand2 _rand3 _rand4
  _rand1="0x$(openssl rand -hex 32 2>/dev/null || echo 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20)"
  _rand2="0x$(openssl rand -hex 32 2>/dev/null || echo 2f2e2d2c2b2a29282726252423222120201f1e1d1c1b1a191817161514131211)"
  _rand3="0x$(openssl rand -hex 20 2>/dev/null || echo a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0)"
  _rand4="0x$(openssl rand -hex 20 2>/dev/null || echo b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3)"
  prompt _spout "SPI outbound"   "0x00000001"
  prompt _spin  "SPI inbound"    "0x00000002"
  prompt _eout  "Enc key out"    "$_rand1"
  prompt _ein   "Enc key in"     "$_rand2"
  prompt _aout  "Auth key out"   "$_rand3"
  prompt _ain   "Auth key in"    "$_rand4"
  _cfg="${CONFIGS_DIR}/${_name}.toml"
  cat > "$_cfg" <<EOF
# virlink — ${_name}
[tunnel]
type      = "gre-fou-ipsec"
mode      = "${_mode}"
local_ip  = "${_local}"
remote_ip = "${_remote}"
cidr      = "${_cidr}"
mtu       = ${_mtu}

[transport]
port               = ${_port}
proto              = "fou"
heartbeat_interval = 10

[security]
encryption   = true
spi_out      = "${_spout}"
spi_in       = "${_spin}"
enc_key_out  = "${_eout}"
enc_key_in   = "${_ein}"
auth_key_out = "${_aout}"
auth_key_in  = "${_ain}"

[tuning]
bbr          = true
channel_size = 10_000

[logging]
level = "info"
EOF
  write_forward_block "$_cfg" "$_mode"
  LAST_CFG_PATH="$_cfg"
}

# ── screens ───────────────────────────────────────────────────────────────────
screen_create() {
  header
  echo -e "  ${BOLD}Create New Tunnel${NC}"; sep
  local ttype
  pick ttype "Tunnel type" \
    "gre-fou        — GRE in UDP (FOU)             fast, no encryption" \
    "ipip-fou       — IPIP in UDP (FOU)            minimal overhead" \
    "bonded-gre-fou — Dual GRE-FOU (ECMP)          2× bandwidth" \
    "l2tpv3         — L2TPv3 over UDP              Layer-2 bridge" \
    "gre-wg         — GRE inside WireGuard         encrypted" \
    "udp-obfs       — Obfuscated UDP AES-256-GCM   DPI bypass / Iran" \
    "gre-fou-ipsec  — GRE-FOU + IPsec ESP          kernel encryption"
  local key="${ttype%%[[:space:]]*}"
  blank
  LAST_CFG_PATH=""
  case "$key" in
    gre-fou)        gen_gre_fou   ;;
    ipip-fou)       gen_ipip_fou  ;;
    bonded-gre-fou) gen_bonded    ;;
    l2tpv3)         gen_l2tpv3   ;;
    gre-wg)         gen_gre_wg   ;;
    udp-obfs)       gen_udp_obfs  ;;
    gre-fou-ipsec)  gen_ipsec    ;;
  esac
  blank
  ok "Config saved: $LAST_CFG_PATH"
  blank
  echo -e "  ${DIM}Config preview:${NC}"; sep
  grep -v '^#' "$LAST_CFG_PATH" | grep -v '^$' | head -30 | sed 's/^/    /'
  blank
  if confirm "Start tunnel now"; then
    require_root; ensure_dirs
    tunnel_start "$(basename "$LAST_CFG_PATH" .toml)"
  fi
  blank; read -rp "  Press Enter to continue..." < /dev/tty
}

screen_manage() {
  header
  echo -e "  ${BOLD}Manage Tunnels${NC}"; sep
  if ! list_tunnels; then read -rp "  Press Enter..." < /dev/tty; return; fi
  local name action
  prompt name "Tunnel name" ""
  [[ -z "$name" ]] && return
  [[ -f "${CONFIGS_DIR}/${name}.toml" ]] || { err "Unknown tunnel: $name"; sleep 2; return; }
  blank
  pick action "Action" \
    "start           — bring tunnel up" \
    "stop            — bring tunnel down" \
    "restart         — stop then start" \
    "status          — show status and logs" \
    "install-service — install as systemd service" \
    "edit            — open config in \$EDITOR" \
    "remove          — delete config"
  action="${action%%[[:space:]]*}"
  require_root; ensure_dirs
  case "$action" in
    start)           tunnel_start "$name" ;;
    stop)            tunnel_stop "$name" ;;
    restart)         tunnel_stop "$name"; tunnel_start "$name" ;;
    status)          tunnel_status "$name" ;;
    install-service) install_systemd "$name" ;;
    edit)            "${EDITOR:-nano}" "${CONFIGS_DIR}/${name}.toml" ;;
    remove)
      if confirm "Remove '$name' (config deleted)"; then
        tunnel_stop "$name" 2>/dev/null || true
        rm -f "${CONFIGS_DIR}/${name}.toml"
        ok "Removed: $name"
      fi
      ;;
  esac
  blank; read -rp "  Press Enter to continue..." < /dev/tty
}

screen_forward() {
  header
  echo -e "  ${BOLD}Add Port Forwarding Rule${NC}"; sep
  if ! list_tunnels; then read -rp "  Press Enter..." < /dev/tty; return; fi
  local name rule cfg
  prompt name "Tunnel name (client-side only)" ""
  cfg="${CONFIGS_DIR}/${name}.toml"
  [[ -f "$cfg" ]] || { err "Not found: $cfg"; sleep 2; return; }
  blank
  echo -e "  ${W}Format:${NC}  listenPort:targetPort   or   listenPort:targetPort/tcp"
  echo -e "  ${DIM}Example: 1000:2000  →  traffic on :1000 forwarded to peer:2000${NC}"
  blank
  prompt rule "Rule" ""
  [[ -z "$rule" ]] && return
  if grep -q '^\[forward\]' "$cfg"; then
    sed -i "s/enabled = false/enabled = true/" "$cfg"
    sed -i "/^rules.*=.*\[/a\\  \"${rule}\"," "$cfg"
  else
    printf '\n[forward]\nenabled = true\nrules   = ["%s"]\n' "$rule" >> "$cfg"
  fi
  ok "Rule added: $rule"
  blank; read -rp "  Press Enter to continue..." < /dev/tty
}

screen_keygen() {
  header
  echo -e "  ${BOLD}Generate WireGuard Keypair${NC}"; sep
  blank
  "$VIRLINK_BIN" keygen
  blank; read -rp "  Press Enter to continue..." < /dev/tty
}

# ── main menu ─────────────────────────────────────────────────────────────────
main() {
  ensure_dirs
  while true; do
    header
    echo -e "  ${BOLD}Main Menu${NC}"; sep
    echo -e "    ${C}1${NC}  Create new tunnel"
    echo -e "    ${C}2${NC}  Manage tunnels  (start / stop / restart / status / service)"
    echo -e "    ${C}3${NC}  Add port forward rule  ${DIM}(client only)${NC}"
    echo -e "    ${C}4${NC}  Generate WireGuard keypair"
    echo -e "    ${C}5${NC}  List all tunnels"
    echo -e "    ${C}6${NC}  Exit"
    blank
    printf "  ${W}?${NC} Choose [1-6]: " >> /dev/tty
    read -r choice < /dev/tty
    case "$choice" in
      1) screen_create ;;
      2) screen_manage ;;
      3) screen_forward ;;
      4) screen_keygen ;;
      5) header; list_tunnels || true; read -rp "  Press Enter..." < /dev/tty ;;
      6) blank; ok "Goodbye."; blank; exit 0 ;;
      *) warn "Invalid choice." ;;
    esac
  done
}

# ── entry point ───────────────────────────────────────────────────────────────
case "${1:-menu}" in
  start)   require_root; ensure_dirs; tunnel_start   "${2:?tunnel name required}" ;;
  stop)    require_root; ensure_dirs; tunnel_stop    "${2:?tunnel name required}" ;;
  restart) require_root; ensure_dirs; tunnel_stop    "${2:?tunnel name required}"; tunnel_start "${2}" ;;
  status)  tunnel_status "${2:?tunnel name required}" ;;
  list)    list_tunnels ;;
  menu)    main ;;
  *)       echo "Usage: $0 [menu|start|stop|restart|status|list] [name]"; exit 1 ;;
esac
