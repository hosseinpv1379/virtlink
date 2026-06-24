# virlink

**Kernel-native virtual tunnel manager** — GRE, IPIP, L2TP, WireGuard, and obfuscated UDP tunnels, all managed through a single binary and interactive setup script.

---

## Quick Start

```bash
# 1. Download
wget https://github.com/YOUR_ORG/virlink/releases/latest/download/virlink
chmod +x virlink setup.sh

# 2. Run interactive setup (as root)
sudo bash setup.sh
```

---

## Tunnel Types

| Type | Description | Encryption | Best For |
|------|-------------|-----------|---------|
| `gre-fou` | GRE in UDP (FOU) | ✗ | Fast site-to-site |
| `ipip-fou` | IPIP in UDP | ✗ | Minimal overhead |
| `bonded-gre-fou` | Dual GRE ECMP | ✗ | 2× bandwidth |
| `l2tpv3` | L2TPv3 over UDP | ✗ | Layer-2 bridge |
| `gre-wg` | GRE inside WireGuard | ✓ | Encrypted routing |
| `udp-obfs` | AES-256-GCM + fake headers | ✓ | **DPI bypass / Iran** |
| `gre-fou-ipsec` | GRE-FOU + IPsec ESP | ✓ | Encrypted FOU |

---

## Setup Script

```
sudo bash setup.sh
```

Interactive menu:

```
  1  Create new tunnel
  2  Manage tunnels  (start / stop / status / install as service)
  3  Add port forward rule
  4  Generate WireGuard keypair
  5  List all tunnels
  6  Exit
```

### Direct commands

```bash
sudo bash setup.sh start   my-tunnel
sudo bash setup.sh stop    my-tunnel
sudo bash setup.sh restart my-tunnel
sudo bash setup.sh status  my-tunnel
sudo bash setup.sh list
```

---

## Manual usage

```bash
# bring up
sudo ./virlink -c configs/my-tunnel.toml

# tear down
sudo ./virlink -c configs/my-tunnel.toml --down

# status
sudo ./virlink -c configs/my-tunnel.toml --status

# generate WireGuard keys
./virlink keygen
```

---

## Config structure

```toml
[tunnel]
type      = "gre-fou"        # tunnel type
mode      = "client"         # client | server
local_ip  = "81.12.35.242"
remote_ip = "5.75.206.15"
cidr      = "10.20.10.0/24"  # client=.1  server=.2
mtu       = 1420

[transport]
port               = 5556
heartbeat_interval = 10       # status log every N seconds

[tuning]
bbr = true

[logging]
level = "info"

# client-only port forwarding
[forward]
enabled = true
rules   = ["1000:2000", "8080:80/tcp"]
```

### udp-obfs extra section

```toml
[obfs]
key     = "shared_secret"   # same on both sides
mask    = "quic"            # noise | quic | dtls
padding = true
```

---

## How it works

- All kernel objects (GRE, IPIP, VXLAN, TUN, routes, addresses) are created **natively via netlink** — no `ip` command subprocesses for core operations.
- `sysctl` parameters are applied by writing directly to `/proc/sys/`.
- `udp-obfs` runs entirely in userspace: Go goroutines encrypt/decrypt every packet with AES-256-GCM before it touches the kernel UDP socket.
- **Ctrl+C** / **SIGTERM** → all kernel objects are removed automatically.

---

## Requirements

- Linux kernel ≥ 5.4
- x86_64 (amd64)
- Root / sudo
- `iptables` (for MSS clamping and port forwarding)
- `linux-modules-extra-$(uname -r)` for L2TPv3 and bonded modes

---

## License

MIT
