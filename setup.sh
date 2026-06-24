#!/usr/bin/env bash
# virlink setup & management script
# https://github.com/your-org/virlink
set -euo pipefail

# ── constants ─────────────────────────────────────────────────────────────────
VIRLINK_BIN="$(cd "$(dirname "$0")" && pwd)/virlink"
CONFIGS_DIR="$(cd "$(dirname "$0")" && pwd)/configs"
PIDS_DIR="/var/run/virlink"
LOGS_DIR="/var/log/virlink"
VERSION="2.0.0"

# ── colors ────────────────────────────────────────────────────────────────────
R='\033[0;31m' G='\033[0;32m' Y='\033[0;33m'
B='\033[0;34m' C='\033[0;36m' W='\033[1;37m'
DIM='\033[2m' BOLD='\033[1m' NC='\033[0m'

# ── helpers ───────────────────────────────────────────────────────────────────
info()    { echo -e "  ${C}→${NC} $*"; }
ok()      { echo -e "  ${G}✓${NC} $*"; }
warn()    { echo -e "  ${Y}⚠${NC} $*"; }
err()     { echo -e "  ${R}✗${NC} $*" >&2; }
die()     { err "$*"; exit 1; }
ask()     { echo -en "  ${W}?${NC} $1: "; }
sep()     { echo -e "${DIM}────────────────────────────────────────────────${NC}"; }
blank()   { echo; }

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
  echo -e "  ${DIM}Kernel Tunnel Manager  v${VERSION}${NC}"
  blank
}

confirm() {
  ask "$1 [y/N]"
  read -r ans
  [[ "${ans,,}" == "y" ]]
}

prompt() {
  local var="$1" msg="$2" def="${3:-}"
  if [[ -n "$def" ]]; then
    ask "$msg ${DIM}[$def]${NC}"
  else
    ask "$msg"
  fi
  read -r val
  if [[ -z "$val" && -n "$def" ]]; then
    eval "$var='$def'"
  else
    eval "$var='$val'"
  fi
}

pick() {
  # pick <varname> <title> <opt1> <opt2> ...
  local var="$1"; shift
  local title="$1"; shift
  local opts=("$@")
  blank
  echo -e "  ${W}${title}${NC}"
  sep
  for i in "${!opts[@]}"; do
    printf "    ${C}%2d${NC}  %s\n" $((i+1)) "${opts[$i]}"
  done
  blank
  while true; do
    ask "Choose [1-${#opts[@]}]"
    read -r n
    if [[ "$n" =~ ^[0-9]+$ ]] && (( n >= 1 && n <= ${#opts[@]} )); then
      eval "$var='${opts[$((n-1))]}'"
      return
    fi
    warn "Invalid choice, try again."
  done
}

require_root() {
  [[ $EUID -eq 0 ]] || die "This action requires root. Run: sudo $0"
}

require_bin() {
  [[ -x "$VIRLINK_BIN" ]] || die "virlink binary not found at $VIRLINK_BIN"
}

ensure_dirs() {
  mkdir -p "$CONFIGS_DIR" "$PIDS_DIR" "$LOGS_DIR"
}

# ── tunnel management ─────────────────────────────────────────────────────────
tunnel_pid_file() { echo "${PIDS_DIR}/$1.pid"; }
tunnel_log_file() { echo "${LOGS_DIR}/$1.log"; }

tunnel_is_running() {
  local pid_file
  pid_file="$(tunnel_pid_file "$1")"
  [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null
}

tunnel_start() {
  local name="$1"
  local cfg="${CONFIGS_DIR}/${name}.toml"
  [[ -f "$cfg" ]] || die "Config not found: $cfg"
  if tunnel_is_running "$name"; then
    warn "Tunnel '$name' is already running (PID $(cat "$(tunnel_pid_file "$name")"))"
    return
  fi
  local log pid_file
  log="$(tunnel_log_file "$name")"
  pid_file="$(tunnel_pid_file "$name")"
  info "Starting tunnel '$name'..."
  nohup "$VIRLINK_BIN" -c "$cfg" > "$log" 2>&1 &
  echo $! > "$pid_file"
  sleep 1
  if tunnel_is_running "$name"; then
    ok "Tunnel '$name' started (PID $(cat "$pid_file"))"
    ok "Log: $log"
  else
    err "Tunnel failed to start. Check log: $log"
    tail -20 "$log" 2>/dev/null || true
  fi
}

tunnel_stop() {
  local name="$1"
  if ! tunnel_is_running "$name"; then
    warn "Tunnel '$name' is not running."
    return
  fi
  local pid
  pid="$(cat "$(tunnel_pid_file "$name")")"
  info "Stopping tunnel '$name' (PID $pid)..."
  kill -TERM "$pid" 2>/dev/null || true
  sleep 2
  if kill -0 "$pid" 2>/dev/null; then
    kill -KILL "$pid" 2>/dev/null || true
  fi
  rm -f "$(tunnel_pid_file "$name")"
  ok "Tunnel '$name' stopped."
}

tunnel_status() {
  local name="$1"
  local cfg="${CONFIGS_DIR}/${name}.toml"
  blank
  echo -e "  ${BOLD}Tunnel: ${C}${name}${NC}"
  sep
  if tunnel_is_running "$name"; then
    local pid
    pid="$(cat "$(tunnel_pid_file "$name")")"
    echo -e "  Status : ${G}RUNNING${NC} (PID $pid)"
  else
    echo -e "  Status : ${R}STOPPED${NC}"
  fi
  if [[ -f "$cfg" ]]; then
    echo -e "  Config : $cfg"
    local type mode local_ip remote_ip
    type=$(grep 'type ' "$cfg" | head -1 | awk -F'"' '{print $2}')
    mode=$(grep 'mode ' "$cfg" | head -1 | awk -F'"' '{print $2}')
    local_ip=$(grep 'local_ip' "$cfg" | awk -F'"' '{print $2}')
    remote_ip=$(grep 'remote_ip' "$cfg" | awk -F'"' '{print $2}')
    echo -e "  Type   : ${Y}${type}${NC}  (${mode})"
    echo -e "  Local  : $local_ip"
    echo -e "  Remote : $remote_ip"
  fi
  if [[ -f "$(tunnel_log_file "$name")" ]]; then
    blank
    echo -e "  ${DIM}Last log lines:${NC}"
    tail -10 "$(tunnel_log_file "$name")" | sed 's/^/    /'
  fi
  blank
}

list_tunnels() {
  local configs
  mapfile -t configs < <(find "$CONFIGS_DIR" -maxdepth 1 -name "*.toml" 2>/dev/null)
  if [[ ${#configs[@]} -eq 0 ]]; then
    warn "No tunnels configured yet."
    return 1
  fi
  blank
  printf "  ${BOLD}%-24s %-16s %-10s %s${NC}\n" "NAME" "TYPE" "STATUS" "REMOTE"
  sep
  for cfg in "${CONFIGS_DIR}"/*.toml; do
    local name type remote status
    name=$(basename "$cfg" .toml)
    type=$(grep 'type ' "$cfg" 2>/dev/null | head -1 | awk -F'"' '{print $2}')
    remote=$(grep 'remote_ip' "$cfg" 2>/dev/null | awk -F'"' '{print $2}')
    if tunnel_is_running "$name"; then
      status="${G}running${NC}"
    else
      status="${R}stopped${NC}"
    fi
    printf "  %-24s %-16s $(echo -e $status)%s  %s\n" "$name" "$type" "" "$remote"
  done
  blank
}

install_systemd() {
  local name="$1"
  local cfg="${CONFIGS_DIR}/${name}.toml"
  [[ -f "$cfg" ]] || die "Config not found: $cfg"
  local svc="/etc/systemd/system/virlink@${name}.service"
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
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "virlink@${name}"
  ok "Installed systemd service: virlink@${name}"
  ok "Start with: systemctl start virlink@${name}"
}

# ── config generators ─────────────────────────────────────────────────────────
write_common_sections() {
  # $1=file $2=port $3=proto $4=hb
  cat >> "$1" << EOF

[transport]
port               = $2
proto              = "$3"
heartbeat_interval = $4

[tuning]
bbr          = true
multipath    = false
channel_size = 10_000

[logging]
level = "info"

[forward]
enabled = false
rules   = []
EOF
}

gen_gre_fou() {
  local name mode local_ip remote_ip cidr port mtu cfg
  collect_base_inputs name mode local_ip remote_ip cidr
  prompt port  "FOU UDP port"  "5556"
  prompt mtu   "MTU"           "1420"
  cfg="${CONFIGS_DIR}/${name}.toml"
  cat > "$cfg" << EOF
# virlink — ${name}
# Generated by setup.sh

[tunnel]
type      = "gre-fou"
mode      = "${mode}"
local_ip  = "${local_ip}"
remote_ip = "${remote_ip}"
cidr      = "${cidr}"
mtu       = ${mtu}
EOF
  write_common_sections "$cfg" "$port" "fou" "10"
  add_forward_section "$cfg" "$mode"
  echo "$cfg"
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
  write_common_sections "$cfg" "$port" "fou" "10"
  add_forward_section "$cfg" "$mode"
  echo "$cfg"
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

[tuning]
bbr          = true
multipath    = true
channel_size = 10_000

[logging]
level = "info"
EOF
  add_forward_section "$cfg" "$mode"
  echo "$cfg"
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

[tuning]
bbr          = true
channel_size = 10_000

[logging]
level = "info"
EOF
  add_forward_section "$cfg" "$mode"
  echo "$cfg"
}

gen_gre_wg() {
  local name mode local_ip remote_ip cidr port mtu cfg
  collect_base_inputs name mode local_ip remote_ip cidr
  prompt port "WireGuard port" "51820"
  prompt mtu  "MTU"           "1380"
  blank
  warn "Run './virlink keygen' to generate WireGuard key pairs."
  local cpriv cpub spriv spub
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

[tuning]
bbr          = true
channel_size = 10_000

[logging]
level = "info"
EOF
  add_forward_section "$cfg" "$mode"
  echo "$cfg"
}

gen_udp_obfs() {
  local name mode local_ip remote_ip cidr port mtu key mask padding cfg
  collect_base_inputs name mode local_ip remote_ip cidr
  prompt port "UDP port (443 recommended)" "443"
  prompt mtu  "MTU"                        "1400"
  blank
  echo -e "  ${W}Obfuscation settings${NC}"
  sep
  prompt key "Shared secret key (same on both sides)" ""
  [[ -z "$key" ]] && die "Key cannot be empty."
  local mask_val
  pick mask_val "Mask mode" \
    "noise  — pure random ciphertext (no header)" \
    "quic   — fake QUIC v1 header on port 443 (recommended for Iran)" \
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

[tuning]
bbr          = true
channel_size = 10_000

[logging]
level = "info"
EOF
  add_forward_section "$cfg" "$mode"
  echo "$cfg"
}

gen_ipsec() {
  local name mode local_ip remote_ip cidr port mtu cfg
  collect_base_inputs name mode local_ip remote_ip cidr
  prompt port "FOU port" "5556"
  prompt mtu  "MTU"      "1380"
  blank
  warn "IPsec keys: generate random values with:"
  warn "  python3 -c \"import os,sys; sys.stdout.write('0x'+os.urandom(32).hex())\""
  local spiout spiin encout encin authout authin
  prompt spiout  "SPI outbound"    "0x00000001"
  prompt spiin   "SPI inbound"     "0x00000002"
  prompt encout  "Enc key out"     "0x$(openssl rand -hex 32 2>/dev/null || echo 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20)"
  prompt encin   "Enc key in"      "0x$(openssl rand -hex 32 2>/dev/null || echo 2f2e2d2c2b2a29282726252423222120201f1e1d1c1b1a191817161514131211)"
  prompt authout "Auth key out"    "0x$(openssl rand -hex 32 2>/dev/null || echo a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2)"
  prompt authin  "Auth key in"     "0x$(openssl rand -hex 32 2>/dev/null || echo b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1)"
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

[tuning]
bbr          = true
channel_size = 10_000

[logging]
level = "info"
EOF
  add_forward_section "$cfg" "$mode"
  echo "$cfg"
}

collect_base_inputs() {
  # sets: $1=name $2=mode $3=local_ip $4=remote_ip $5=cidr
  local _name _mode _local _remote _cidr
  blank
  prompt _name   "Tunnel name (e.g. my-tunnel)" ""
  [[ -z "$_name" ]] && die "Name cannot be empty."
  _name="${_name// /-}"   # replace spaces with dashes
  pick _mode "Mode" "client" "server"
  blank
  prompt _local  "This server's public IP" ""
  prompt _remote "Peer server's public IP" ""
  prompt _cidr   "Overlay subnet (CIDR)"  "10.20.10.0/24"
  eval "$1='$_name'"
  eval "$2='$_mode'"
  eval "$3='$_local'"
  eval "$4='$_remote'"
  eval "$5='$_cidr'"
}

add_forward_section() {
  local cfg="$1" mode="$2"
  if [[ "$mode" == "client" ]]; then
    cat >> "$cfg" << 'EOF'

# ── port forwarding (client only) ────────────────────────────────────────────
[forward]
enabled = false
rules   = [
  # "1000:2000",     # :1000 → peer:2000 (tcp+udp)
  # "8080:80/tcp",
]
EOF
  fi
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
    "gre-fou-ipsec  — GRE-FOU + IPsec ESP               encrypted + FOU"
  local key="${ttype%%[[:space:]]*}"
  blank
  local cfg_path
  case "$key" in
    gre-fou)        cfg_path=$(gen_gre_fou)    ;;
    ipip-fou)       cfg_path=$(gen_ipip_fou)   ;;
    bonded-gre-fou) cfg_path=$(gen_bonded)     ;;
    l2tpv3)         cfg_path=$(gen_l2tpv3)     ;;
    gre-wg)         cfg_path=$(gen_gre_wg)     ;;
    udp-obfs)       cfg_path=$(gen_udp_obfs)   ;;
    gre-fou-ipsec)  cfg_path=$(gen_ipsec)      ;;
  esac
  blank
  ok "Config saved: $cfg_path"
  blank
  echo -e "  ${DIM}Config preview:${NC}"
  sep
  grep -v '^#' "$cfg_path" | grep -v '^$' | head -30 | sed 's/^/    /'
  blank
  if confirm "Start tunnel now"; then
    require_root
    ensure_dirs
    local name
    name=$(basename "$cfg_path" .toml)
    tunnel_start "$name"
  fi
  blank
  read -rp "  Press Enter to continue..."
}

screen_manage() {
  header
  echo -e "  ${BOLD}Manage Tunnels${NC}"
  sep
  if ! list_tunnels; then
    read -rp "  Press Enter to continue..."
    return
  fi
  local name
  prompt name "Tunnel name" ""
  [[ -z "$name" ]] && return
  [[ -f "${CONFIGS_DIR}/${name}.toml" ]] || { err "Unknown tunnel: $name"; sleep 2; return; }
  blank
  local action
  pick action "Action" \
    "start   — bring tunnel up" \
    "stop    — bring tunnel down" \
    "restart — stop then start" \
    "status  — show status and logs" \
    "install-service — install as systemd service" \
    "edit    — open config in editor" \
    "remove  — delete tunnel config"
  action="${action%%[[:space:]]*}"
  require_root
  ensure_dirs
  case "$action" in
    start)           tunnel_start "$name" ;;
    stop)            tunnel_stop "$name" ;;
    restart)         tunnel_stop "$name"; tunnel_start "$name" ;;
    status)          tunnel_status "$name" ;;
    install-service) install_systemd "$name" ;;
    edit)
      local editor="${EDITOR:-nano}"
      "$editor" "${CONFIGS_DIR}/${name}.toml"
      ;;
    remove)
      if confirm "Remove tunnel '$name' (config will be deleted)"; then
        tunnel_stop "$name" 2>/dev/null || true
        rm -f "${CONFIGS_DIR}/${name}.toml"
        ok "Removed: $name"
      fi
      ;;
  esac
  blank
  read -rp "  Press Enter to continue..."
}

screen_setup_forward() {
  header
  echo -e "  ${BOLD}Add Port Forwarding Rule${NC}"
  sep
  if ! list_tunnels; then
    read -rp "  Press Enter to continue..."
    return
  fi
  local name
  prompt name "Tunnel name (client only)" ""
  local cfg="${CONFIGS_DIR}/${name}.toml"
  [[ -f "$cfg" ]] || { err "Not found: $cfg"; sleep 2; return; }
  blank
  echo -e "  ${W}Rule format:${NC}  listenPort:targetPort  or  listenPort:targetPort/tcp"
  local rule
  prompt rule "Rule (e.g. 1000:2000)" ""
  [[ -z "$rule" ]] && return
  # insert rule into [forward] section
  if grep -q '^\[forward\]' "$cfg"; then
    sed -i "/^enabled = false/s/enabled = false/enabled = true/" "$cfg"
    sed -i "/^rules.*=.*\[/a\\  \"${rule}\"," "$cfg"
    ok "Rule added: $rule"
  else
    cat >> "$cfg" << EOF

[forward]
enabled = true
rules   = ["${rule}"]
EOF
    ok "Forward section added with rule: $rule"
  fi
  blank
  read -rp "  Press Enter to continue..."
}

screen_keygen() {
  header
  echo -e "  ${BOLD}Generate WireGuard Keypair${NC}"
  sep
  require_bin
  blank
  "$VIRLINK_BIN" keygen
  blank
  read -rp "  Press Enter to continue..."
}

# ── main ──────────────────────────────────────────────────────────────────────
main() {
  require_bin
  mkdir -p "$CONFIGS_DIR"

  while true; do
    header
    echo -e "  ${BOLD}Main Menu${NC}"
    sep
    echo -e "    ${C}1${NC}  Create new tunnel"
    echo -e "    ${C}2${NC}  Manage tunnels  (start / stop / status / install service)"
    echo -e "    ${C}3${NC}  Add port forward rule"
    echo -e "    ${C}4${NC}  Generate WireGuard keypair"
    echo -e "    ${C}5${NC}  List all tunnels"
    echo -e "    ${C}6${NC}  Exit"
    blank
    ask "Choose [1-6]"
    read -r choice
    case "$choice" in
      1) screen_create ;;
      2) screen_manage ;;
      3) screen_setup_forward ;;
      4) screen_keygen ;;
      5)
        header
        list_tunnels || true
        read -rp "  Press Enter to continue..."
        ;;
      6) blank; ok "Goodbye."; blank; exit 0 ;;
      *) warn "Invalid choice." ;;
    esac
  done
}

# allow direct sub-commands: ./setup.sh start <name>
case "${1:-menu}" in
  start)   require_root; ensure_dirs; tunnel_start "${2:?name required}" ;;
  stop)    require_root; ensure_dirs; tunnel_stop  "${2:?name required}" ;;
  restart) require_root; ensure_dirs; tunnel_stop  "${2:?name required}"; tunnel_start "${2}" ;;
  status)  tunnel_status "${2:?name required}" ;;
  list)    list_tunnels ;;
  menu)    main ;;
  *)       echo "Usage: $0 [menu|start|stop|restart|status|list] [name]"; exit 1 ;;
esac
