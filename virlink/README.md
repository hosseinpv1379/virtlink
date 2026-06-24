# virlink

**Kernel-native virtual tunnel manager for Linux.**  
Build encrypted, obfuscated, or high-performance tunnels between two servers — managed by a single binary and an interactive setup script.

[![Release](https://img.shields.io/github/v/release/hosseinpv1379/virtlink?label=release)](https://github.com/hosseinpv1379/virtlink/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/platform-Linux%20x86__64-lightgrey)
![Kernel](https://img.shields.io/badge/kernel-%E2%89%A55.4-important)

---

## Quick Install

Run this on **both** servers (as root):

```bash
bash <(curl -fsSL https://github.com/hosseinpv1379/virtlink/releases/latest/download/setup.sh)
```

Or download manually:

```bash
wget https://github.com/hosseinpv1379/virtlink/releases/latest/download/virlink
wget https://github.com/hosseinpv1379/virtlink/releases/latest/download/setup.sh
chmod +x virlink
sudo bash setup.sh
```

---

## Tunnel Types

| Type | Description | Encrypted | Best For |
|------|-------------|:---------:|----------|
| `gre-fou` | GRE encapsulated in UDP (FOU) | ✗ | Fast site-to-site link |
| `ipip-fou` | IPIP encapsulated in UDP | ✗ | Lowest overhead |
| `bonded-gre-fou` | Dual GRE with ECMP | ✗ | 2× bandwidth |
| `l2tpv3` | L2TPv3 over UDP | ✗ | Layer-2 Ethernet bridge |
| `gre-wg` | GRE tunnelled inside WireGuard | ✓ | Encrypted routing |
| `vxlan-wg` | VXLAN over WireGuard | ✓ | Encrypted L2 overlay |
| `gre-fou-ipsec` | GRE-FOU + IPsec ESP | ✓ | Kernel-level encryption |
| `udp-obfs` | AES-256-GCM + fake protocol headers | ✓ | **DPI bypass / censorship** |

---

## Interactive Setup

```bash
sudo bash setup.sh
```

```
  ██╗   ██╗██╗██████╗ ██╗     ██╗███╗   ██╗██╗  ██╗
  ██║   ██║██║██╔══██╗██║     ██║████╗  ██║██║ ██╔╝
  ██║   ██║██║██████╔╝██║     ██║██╔██╗ ██║█████╔╝
  ╚██╗ ██╔╝██║██╔══██╗██║     ██║██║╚██╗██║██╔═██╗
   ╚████╔╝ ██║██║  ██║███████╗██║██║ ╚████║██║  ██╗
    ╚═══╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝

  Kernel Tunnel Manager  v2.0.0

  1  Create new tunnel
  2  Manage tunnels  (start / stop / restart / status / install as service)
  3  Add port forward rule
  4  Generate WireGuard keypair
  5  List all tunnels
  6  Exit
```

### Direct commands

```bash
sudo bash setup.sh start    <tunnel-name>
sudo bash setup.sh stop     <tunnel-name>
sudo bash setup.sh restart  <tunnel-name>
sudo bash setup.sh status   <tunnel-name>
sudo bash setup.sh list
```

---

## Config File

Configs are stored in `configs/<name>.toml` and generated automatically by `setup.sh`.  
You can also write them by hand:

```toml
[tunnel]
type      = "gre-fou"        # see tunnel types above
mode      = "client"         # client | server
local_ip  = "81.12.35.242"   # this server's public IP
remote_ip = "5.75.206.15"    # peer server's public IP
cidr      = "10.20.10.0/24"  # overlay subnet  (client → .1  server → .2)
mtu       = 1420

[transport]
port               = 5556
heartbeat_interval = 10      # heartbeat log every N seconds

[tuning]
bbr = true

[logging]
level = "info"   # debug | info | warn | error

# ── client-only port forwarding ───────────────────────────────────────────────
[forward]
enabled = true
rules   = ["1000:2000", "8080:80/tcp"]
# → local :1000  →  peer overlay :2000
# → local :8080  →  peer overlay :80  (TCP)
```

### Extra section for `udp-obfs`

```toml
[obfs]
key     = "your_shared_secret"   # same on both sides
mask    = "quic"                 # noise | quic | dtls
padding = true                   # add random padding to defeat length analysis
```

| mask | Disguises traffic as |
|------|----------------------|
| `noise` | Random UDP noise |
| `quic` | QUIC v1 (Google / Cloudflare) |
| `dtls` | DTLS 1.2 (WebRTC) |

---

## Manual Usage

```bash
# bring the tunnel up (daemon mode — press Ctrl+C to tear down)
sudo ./virlink -c configs/my-tunnel.toml

# tear down immediately
sudo ./virlink -c configs/my-tunnel.toml --down

# show current status & stats
sudo ./virlink -c configs/my-tunnel.toml --status

# generate a WireGuard keypair
./virlink keygen
```

---

## How It Works

- **Native netlink** — all kernel objects (GRE, IPIP, VXLAN, TUN, addresses, routes) are created via the kernel's netlink API. No `ip` command subprocesses for core operations.  
- **Direct sysctl** — parameters like `net.ipv4.ip_forward` and BBR are applied by writing to `/proc/sys/` — no `sysctl` command needed.  
- **Daemon mode** — the binary blocks after bringing the tunnel up, printing a live heartbeat (interface state, Rx/Tx bytes) every N seconds.  
- **Clean shutdown** — `Ctrl+C` / `SIGTERM` automatically removes all kernel objects (interfaces, routes, iptables rules).  
- **udp-obfs** — fully userspace: a TUN device + Go goroutines encrypt every packet with AES-256-GCM before it reaches the kernel UDP socket.

---

## Requirements

| Requirement | Detail |
|-------------|--------|
| OS | Linux (Ubuntu 20.04+ recommended) |
| Arch | x86_64 (amd64) |
| Kernel | ≥ 5.4 |
| Privileges | root / sudo |
| `iptables` | MSS clamping & port forwarding |
| Kernel modules | `linux-modules-extra-$(uname -r)` for L2TPv3, bonded, and VXLAN modes |

```bash
# install kernel modules (Ubuntu/Debian)
apt install linux-modules-extra-$(uname -r)
```

---

## Repository Branches

| Branch | Contents |
|--------|----------|
| `main` | Binary (`virlink`) + `setup.sh` — public release |
| `source` | Full Go source code — for development |

---

## License

[MIT](LICENSE)
