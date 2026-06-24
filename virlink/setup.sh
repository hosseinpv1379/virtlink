#!/usr/bin/env bash
# virlink — kernel tunnel manager setup & management script
# https://github.com/hosseinpv1379/virtlink
set -euo pipefail

# ── constants ─────────────────────────────────────────────────────────────────
GITHUB_REPO="hosseinpv1379/virtlink"
INSTALL_DIR="/opt/virlink"
VIRLINK_BIN="${INSTALL_DIR}/virlink"
CONFIGS_DIR="${INSTALL_DIR}/configs"
PIDS_DIR="/var/run/virlink"
LOGS_DIR="/var/log/virlink"
SCRIPT_VERSION="2.1.0"

# Runtime state (set by check_update)
UPDATE_AVAILABLE=0
LATEST_TAG=""
LAST_CFG_PATH=""   # returned by gen_* functions (avoids $() subshell capture)

# ── colors ────────────────────────────────────────────────────────────────────
R='\033[0;31m' G='\033[0;32m' Y='\033[0;33m'
B='\033[0;34m' C='\033[0;36m' W='\033[1;37m'
DIM='\033[2m' BOLD='\033[1m' NC='\033[0m'

# ── I/O helpers ───────────────────────────────────────────────────────────────
# All interactive output goes to /dev/tty so prompts are visible even when the
# caller is inside a $() subshell (which captures stdout).
tty_out()   { printf '%b' "$@" > /dev/tty; }
tty_line()  { printf '%b\n' "$@" > /dev/tty; }

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
  # prompt <varname> <message> [default]
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
  # pick <varname> <title> <opt1> [opt2 ...]
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

# ── auto-install (runs when invoked via curl | bash or bash <(curl ...)) ──────
_is_piped_install() {
  # We are "piped" if the script path isn't a normal persistent file, or binary
  # is not yet installed.
  [[ "$0" == /dev/fd/* ]] || [[ "$0" == /proc/self/fd/* ]] || \
  [[ ! -f "$VIRLINK_BIN" ]]
}

do_install() {
  echo -e "\n${BOLD}${B}  virlink installer${NC}\n"
  echo -e "  ${C}→${NC} Installing to ${INSTALL_DIR}..."
  mkdir -p "${INSTALL_DIR}" "${INSTALL_DIR}/configs"

  echo -e "  ${C}→${NC} Downloading virlink binary..."
  curl -fsSL "https://github.com/${GITHUB_REPO}/releases/latest/download/virlink" \
    -o "${INSTALL_DIR}/virlink"
  chmod +x "${INSTALL_DIR}/virlink"

  echo -e "  ${C}→${NC} Downloading setup script..."
  curl -fsSL "https://github.com/${GITHUB_REPO}/releases/latest/download/setup.sh" \
    -o "${INSTALL_DIR}/setup.sh"
  chmod +x "${INSTALL_DIR}/setup.sh"

  # symlinks in PATH
  ln -sf "${INSTALL_DIR}/virlink"  /usr/local/bin/virlink   2>/dev/null || true
  ln -sf "${INSTALL_DIR}/setup.sh" /usr/local/bin/virlink-setup 2>/dev/null || true

  local ver
  ver=$("${INSTALL_DIR}/virlink" --version 2>/dev/null || echo "?")
  echo -e "  ${G}✓${NC} Installed ${ver}"
  echo -e "  ${G}✓${NC} Symlinks: ${W}/usr/local/bin/virlink${NC}  ${W}virlink-setup${NC}"
  echo
  exec "${INSTALL_DIR}/setup.sh"
}

# ── version / update ──────────────────────────────────────────────────────────
check_update() {
  # Runs silently; sets UPDATE_AVAILABLE and LATEST_TAG.
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
  if [[ -z "$LATEST_TAG" ]]; then
    info "Checking latest release..."
    check_update
  fi
  if (( ! UPDATE_AVAILABLE )); then
    ok "Already up to date."
    blank
    press_enter
    return
  fi
  info "Downloading virlink ${LATEST_TAG}..."
  curl -fsSL "https://github.com/${GITHUB_REPO}/releases/latest/download/virlink" \
    -o "${VIRLINK_BIN}.new"
  chmod +x "${VIRLINK_BIN}.new"
  mv "${VIRLINK_BIN}.new" "$VIRLINK_BIN"

  info "Updating setup script..."
  curl -fsSL "https://github.com/${GITHUB_REPO}/releases/latest/download/setup.sh" \
    -o "${INSTALL_DIR}/setup.sh.new"
  chmod +x "${INSTALL_DIR}/setup.sh.new"
  mv "${INSTALL_DIR}/setup.sh.new" "${INSTALL_DIR}/setup.sh"

  ok "Updated to ${LATEST_TAG}  —  restarting setup..."
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

  # version + update badge
  local cur_ver
  cur_ver=$("$VIRLINK_BIN" --version 2>/dev/null | grep -oE 'v[0-9.]+' || echo "?")
  if (( UPDATE_AVAILABLE )); then
    echo -e "  ${DIM}binary ${cur_ver}${NC}   ${Y}${BOLD}⬆  Update available → ${LATEST_TAG}${NC}"
    echo -e "  ${DIM}(choose option 6 in the menu to update)${NC}"
  else
    echo -e "  ${DIM}binary ${cur_ver}  ✓ up to date${NC}"
  fi
  blank
}

# ── prerequisite guards ───────────────────────────────────────────────────────
require_root() { [[ $EUID -eq 0 ]] || die "Requires root — run: sudo virlink-setup"; }
require_bin()  { [[ -x "$VIRLINK_BIN" ]] || die "virlink binary not found at $VIRLINK_BIN — reinstall."; }
ensure_dirs()  { mkdir -p "$CONFIGS_DIR" "$PIDS_DIR" "$LOGS_DIR"; }

# ── tunnel management ─────────────────────────────────────────────────────────
tunnel_pid_file() { echo "${PIDS_DIR}/$1.pid"; }
tunnel_log_file() { echo "${LOGS_DIR}/$1.log"; }

tunnel_is_running() {
  local f
  f="$(tunnel_pid_file "$1")"
  [[ -f "$f" ]] && kill -0 "$(cat "$f")" 2>/dev/null
}

tunnel_start() {
  local name="$1" cfg log pid_file
  cfg="${CONFIGS_DIR}/${name}.toml"
  [[ -f "$cfg" ]] || die "Config not found: $cfg"
  if tunnel_is_running "$name"; then
    warn "Tunnel '${name}' already running (PID $(cat "$(tunnel_pid_file "$name")"))"
    return
  fi
  log="$(tunnel_log_file "$name")"
  pid_file="$(tunnel_pid_file "$name")"
  info "Starting tunnel '${name}'..."
  nohup "$VIRLINK_BIN" -c "$cfg" > "$log" 2>&1 &
  echo $! > "$pid_file"
  sleep 1
  if tunnel_is_running "$name"; then
    ok "Tunnel '${name}' started (PID $(cat "$pid_file"))"
    ok "Log: $log"
  else
    err "Tunnel failed to start. Log: $log"
    tail -20 "$log" 2>/dev/null || true
  fi
}

tunnel_stop() {
  local name="$1" pid
  if ! tunnel_is_running "$name"; then
    warn "Tunnel '${name}' is not running."
    return
  fi
  pid="$(cat "$(tunnel_pid_file "$name")")"
  info "Stopping tunnel '${name}' (PID ${pid})..."
  kill -TERM "$pid" 2>/dev/null || true
  sleep 2
  kill -0 "$pid" 2>/dev/null && { kill -KILL "$pid" 2>/dev/null || true; }
  rm -f "$(tunnel_pid_file "$name")"
  ok "Tunnel '${name}' stopped."
}

tunnel_status() {
  local name="$1" cfg
  cfg="${CONFIGS_DIR}/${name}.toml"
  blank
  echo -e "  ${BOLD}Tunnel: ${C}${name}${NC}"
  sep
  if tunnel_is_running "$name"; then
    local pid; pid="$(cat "$(tunnel_pid_file "$name")")"
    echo -e "  Status : ${G}RUNNING${NC} (PID ${pid})"
  else
    echo -e "  Status : ${R}STOPPED${NC}"
  fi
  if [[ -f "$cfg" ]]; then
    local type mode local_ip remote_ip
    type=$(grep 'type '     "$cfg" 2>/dev/null | head -1 | awk -F'"' '{print $2}')
    mode=$(grep 'mode '     "$cfg" 2>/dev/null | head -1 | awk -F'"' '{print $2}')
    local_ip=$(grep 'local_ip'  "$cfg" 2>/dev/null | awk -F'"' '{print $2}')
    remote_ip=$(grep 'remote_ip' "$cfg" 2>/dev/null | awk -F'"' '{print $2}')
    echo -e "  Config : $cfg"
    echo -e "  Type   : ${Y}${type}${NC}  (${mode})"
    echo -e "  Local  : $local_ip  →  Remote: $remote_ip"
  fi
  if [[ -f "$(tunnel_log_file "$name")" ]]; then
    blank
    echo -e "  ${DIM}Last 10 log lines:${NC}"
    tail -10 "$(tunnel_log_file "$name")" | sed 's/^/    /'
  fi
  blank
}

list_tunnels() {
  local cfgs=()
  mapfile -t cfgs < <(find "$CONFIGS_DIR" -maxdepth 1 -name "*.toml" 2>/dev/null | sort)
  if [[ ${#cfgs[@]} -eq 0 ]]; then
    warn "No tunnels configured yet."
    return 1
  fi
  blank
  printf "  ${BOLD}%-26s %-18s %-10s %s${NC}\n" "NAME" "TYPE" "STATUS" "REMOTE"
  sep
  local cfg name type remote status
  for cfg in "${cfgs[@]}"; do
    name=$(basename "$cfg" .toml)
    type=$(grep 'type '    "$cfg" 2>/dev/null | head -1 | awk -F'"' '{print $2}')
    remote=$(grep 'remote_ip' "$cfg" 2>/dev/null | awk -F'"' '{print $2}')
    if tunnel_is_running "$name"; then
      status="${G}running${NC}"
    else
      status="${R}stopped${NC}"
    fi
    printf "  %-26s %-18s " "$name" "$type"
    echo -e "${status}   $remote"
  done
  blank
}

install_systemd() {
  local name="$1" cfg svc
  cfg="${CONFIGS_DIR}/${name}.toml"
  [[ -f "$cfg" ]] || die "Config not found: $cfg"
  svc="/etc/systemd/system/virlink@${name}.service"
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
  ok "Installed: virlink@${name}"
  ok "Enable now: systemctl start virlink@${name}"
}

# ── config helpers ────────────────────────────────────────────────────────────
collect_base_inputs() {
  # Sets caller's variables: $1=name $2=mode $3=local_ip $4=remote_ip $5=cidr
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
  # write_transport <file> <port> <proto> <hb_interval>
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
  # "1000:2000",    # listen :1000  →  peer:2000 (tcp+udp)
  # "8080:80/tcp",
]
EOF
  fi
}

# ── config generators ─────────────────────────────────────────────────────────
# Each sets LAST_CFG_PATH instead of echoing — avoids blank-prompt bug from $().

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
  echo -e "  ${W}Obfuscation settings${NC}"
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
  local spiout spiin encout encin authout authin
  collect_base_inputs name mode local_ip remote_ip cidr
  prompt port "FOU port" "5556"
  prompt mtu  "MTU"      "1380"
  blank
  warn "Generate random keys with:"
  warn "  python3 -c \"import os,sys; sys.stdout.write('0x'+os.urandom(32).hex())\""
  prompt spiout  "SPI outbound"  "0x00000001"
  prompt spiin   "SPI inbound"   "0x00000002"
  local rh32; rh32=$(openssl rand -hex 32 2>/dev/null || echo "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
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
  warn "ICMP tunnel requires CAP_NET_RAW (root). Both sides must run as root."
  warn "Firewall must allow ICMP (protocol 1) between the two IPs."
  cfg="${CONFIGS_DIR}/${name}.toml"
  cat > "$cfg" << EOF
# virlink — ${name}  (ICMP Echo tunnel, IP proto 1)
# Wraps IP packets inside ICMP Echo Requests for DPI evasion.
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
  warn "BIP uses IP protocol 58 (same number as ICMPv6) for DPI evasion."
  warn "Requires CAP_NET_RAW (root). Firewall must pass proto 58."
  cfg="${CONFIGS_DIR}/${name}.toml"
  cat > "$cfg" << EOF
# virlink — ${name}  (BIP tunnel, IP proto 58 / ICMPv6-number over IPv4)
# Uses an uncommon IPv4 protocol number to evade DPI.
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
    *) die "Unknown tunnel type: $key" ;;
  esac

  blank
  ok "Config saved: ${LAST_CFG_PATH}"
  blank
  echo -e "  ${DIM}Config preview:${NC}"
  sep
  grep -v '^#' "${LAST_CFG_PATH}" | grep -v '^$' | head -30 | sed 's/^/    /'
  blank

  if confirm "Start tunnel now"; then
    require_root
    ensure_dirs
    tunnel_start "$(basename "${LAST_CFG_PATH}" .toml)"
  fi
  blank
  press_enter
}

screen_manage() {
  header
  echo -e "  ${BOLD}Manage Tunnels${NC}"
  sep
  if ! list_tunnels; then
    press_enter
    return
  fi
  local name
  prompt name "Tunnel name" ""
  [[ -z "$name" ]] && return
  [[ -f "${CONFIGS_DIR}/${name}.toml" ]] || { err "Unknown tunnel: $name"; sleep 2; return; }

  blank
  local action
  pick action "Action" \
    "start          — bring tunnel up" \
    "stop           — bring tunnel down" \
    "restart        — stop then start" \
    "status         — show status and logs" \
    "install-service — install as systemd service" \
    "edit           — open config in editor" \
    "remove         — delete tunnel config"
  action="${action%%[[:space:]]*}"

  require_root
  ensure_dirs
  case "$action" in
    start)           tunnel_start  "$name" ;;
    stop)            tunnel_stop   "$name" ;;
    restart)         tunnel_stop   "$name"; tunnel_start "$name" ;;
    status)          tunnel_status "$name" ;;
    install-service) install_systemd "$name" ;;
    edit)
      local editor="${EDITOR:-nano}"
      "$editor" "${CONFIGS_DIR}/${name}.toml"
      ;;
    remove)
      if confirm "Remove tunnel '${name}' (config deleted)"; then
        tunnel_stop "$name" 2>/dev/null || true
        rm -f "${CONFIGS_DIR}/${name}.toml"
        ok "Removed: $name"
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
  if ! list_tunnels; then
    press_enter
    return
  fi
  local name
  prompt name "Tunnel name (client-mode only)" ""
  local cfg="${CONFIGS_DIR}/${name}.toml"
  [[ -f "$cfg" ]] || { err "Not found: $cfg"; sleep 2; return; }
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
    ok "Forward section added with rule: $rule"
  fi
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

  # background version check on first run
  check_update &
  local _bg=$!

  while true; do
    # collect the background check result if it has finished
    if [[ -n "${_bg:-}" ]]; then
      wait "$_bg" 2>/dev/null || true
      _bg=""
    fi

    header
    echo -e "  ${BOLD}Main Menu${NC}"
    sep
    echo -e "    ${C}1${NC}  Create new tunnel"
    echo -e "    ${C}2${NC}  Manage tunnels  (start / stop / status / service)"
    echo -e "    ${C}3${NC}  Add port forward rule"
    echo -e "    ${C}4${NC}  Generate WireGuard keypair"
    echo -e "    ${C}5${NC}  List all tunnels"
    if (( UPDATE_AVAILABLE )); then
      echo -e "    ${Y}6${NC}  ${Y}Update available${NC} → ${LATEST_TAG}"
    else
      echo -e "    ${C}6${NC}  Check for updates"
    fi
    echo -e "    ${C}7${NC}  Exit"
    blank
    tty_out "  ${W}?${NC} Choose [1-7]: "
    read -r choice < /dev/tty
    case "$choice" in
      1) screen_create ;;
      2) screen_manage ;;
      3) screen_setup_forward ;;
      4) screen_keygen ;;
      5)
        header
        list_tunnels || true
        press_enter
        ;;
      6) screen_update ;;
      7) blank; ok "Goodbye."; blank; exit 0 ;;
      *) warn "Invalid choice." ;;
    esac
  done
}

# ── entry point ───────────────────────────────────────────────────────────────
# Auto-install when run via curl | bash or binary is missing
if _is_piped_install; then
  [[ $EUID -eq 0 ]] || { echo "Run as root: sudo bash <(curl ...)"; exit 1; }
  do_install
fi

# Direct sub-commands: setup.sh start <name>
case "${1:-menu}" in
  start)    require_root; ensure_dirs; tunnel_start  "${2:?tunnel name required}" ;;
  stop)     require_root; ensure_dirs; tunnel_stop   "${2:?tunnel name required}" ;;
  restart)  require_root; ensure_dirs; tunnel_stop   "${2:?tunnel name required}"; \
                                       tunnel_start  "${2}" ;;
  status)   tunnel_status "${2:?tunnel name required}" ;;
  list)     list_tunnels ;;
  update)   require_root; check_update; do_self_update ;;
  menu)     main ;;
  *)        echo "Usage: $0 [menu|start|stop|restart|status|list|update] [name]"; exit 1 ;;
esac
