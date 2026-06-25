# virlink

**Kernel-native virtual tunnel manager** — GRE, IPIP, L2TP, WireGuard, obfuscated UDP, raw ICMP/TCP/UDP/BIP tunnels, all managed through a single binary and interactive setup script.

[![Release](https://img.shields.io/github/v/release/hosseinpv1379/virtlink)](https://github.com/hosseinpv1379/virtlink/releases/latest)
[![Platform](https://img.shields.io/badge/platform-linux%20amd64-blue)](https://github.com/hosseinpv1379/virtlink/releases/latest)

---

## Quick Start

```bash
# Install (as root)
sudo bash <(curl -fsSL https://github.com/hosseinpv1379/virtlink/releases/latest/download/setup.sh)
```

This downloads the binary and setup script to `/opt/virlink`, creates symlinks in `/usr/local/bin`, and launches the interactive menu.

After install, run from anywhere:

```bash
sudo virlink-setup
```

---

## Tunnel Types

| Type | Protocol | Description | Encryption | Best For |
|------|----------|-------------|-----------|---------|
| `gre-fou` | UDP | GRE wrapped in UDP (FOU) | ✗ | Fast site-to-site |
| `ipip-fou` | UDP | IPIP wrapped in UDP | ✗ | Minimal overhead |
| `bonded-gre-fou` | UDP | Dual GRE-FOU ECMP | ✗ | 2× bandwidth |
| `l2tpv3` | UDP | L2TPv3 over UDP | ✗ | Layer-2 bridge |
| `gre-wg` | UDP | GRE inside WireGuard | ✓ | Encrypted routing |
| `udp-obfs` | UDP | AES-256-GCM + fake headers | ✓ | **DPI bypass / Iran** |
| `gre-fou-ipsec` | UDP | GRE-FOU + IPsec ESP | ✓ | Encrypted FOU |
| `gre` | IP/47 | Plain kernel GRE | ✗ | No UDP wrapper |
| `tcp` | TCP | User-space TCP tunnel | ✗ | Firewall-friendly |
| `udp` | UDP | User-space plain UDP | ✗ | Simple UDP transport |
| `icmp` | IP/1 | ICMP Echo carrier | ✗ | DPI evasion |
| `bip` | IP/58 | Proto-58 carrier (ICMPv6 number) | ✗ | DPI evasion |

---

## Interactive Menu

```
sudo virlink-setup

  1  Create new tunnel
  2  Manage tunnels  (start / stop / status / install as service)
  3  Add port forward rule
  4  Generate WireGuard keypair
  5  List all tunnels
  6  Update virlink  ← shows update badge when a new release is available
  7  Exit
```

**Version check** — on every menu open the binary version is compared against the latest GitHub release. If an update is available, option 6 is highlighted in yellow. The update downloads both the binary and setup script atomically, then restarts.

### Direct sub-commands

```bash
sudo virlink-setup start   my-tunnel
sudo virlink-setup stop    my-tunnel
sudo virlink-setup restart my-tunnel
sudo virlink-setup status  my-tunnel
sudo virlink-setup list
sudo virlink-setup update      # one-shot update check + apply
```

---

## Manual usage

```bash
# bring up (blocks — tunnel lives while process runs)
sudo virlink -c /opt/virlink/configs/my-tunnel.toml

# tear down
sudo virlink -c /opt/virlink/configs/my-tunnel.toml --down

# status
sudo virlink -c /opt/virlink/configs/my-tunnel.toml --status

# generate WireGuard keys
virlink keygen

# print version
virlink --version
```

---

## Config structure

```toml
[tunnel]
type      = "gre-fou"        # see tunnel types table above
mode      = "client"         # client | server
local_ip  = "81.12.35.242"   # this server's public IP
remote_ip = "5.75.206.15"    # peer's public IP
cidr      = "10.20.10.0/24"  # client → .1 / server → .2
mtu       = 1420

[transport]
port               = 5556
heartbeat_interval = 10      # status log every N seconds

[tuning]
bbr          = true
channel_size = 10_000

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

### Raw-socket tunnels (gre / icmp / bip)

These use IP-level raw sockets — no `port` needed:

```toml
[tunnel]
type      = "icmp"
mode      = "client"
local_ip  = "81.12.35.242"
remote_ip = "5.75.206.15"
cidr      = "10.20.10.0/24"
mtu       = 1472

[transport]
heartbeat_interval = 10
```

---

## How it works

- All kernel objects (GRE, IPIP, TUN/TAP, routes, addresses) are created **natively via netlink** — no `ip` sub-process for core operations.
- `sysctl` parameters are written directly to `/proc/sys/`.
- `udp-obfs` runs entirely in userspace: every packet is AES-256-GCM encrypted before it touches the UDP socket.
- `icmp` / `bip` / `tcp` / `udp` use a TUN device + Go goroutines for the transport; kernel handles IP routing normally.
- **Ctrl+C** / **SIGTERM** → all kernel objects and iptables rules are removed automatically.
- Goroutines hold private references to sockets/file descriptors so shutdown races cannot produce nil-pointer panics (v2.1.0+).

---

## Requirements

- Linux kernel ≥ 5.4
- x86_64 (amd64)
- Root / sudo
- `iptables` (MSS clamping and port forwarding)
- `linux-modules-extra-$(uname -r)` — needed for L2TPv3 and bonded modes
- `curl` — required by setup.sh for downloads and install

---

## Files

| Path | Description |
|------|-------------|
| `/opt/virlink/virlink` | binary |
| `/opt/virlink/setup.sh` | this script |
| `/opt/virlink/configs/*.toml` | tunnel configs |
| `/var/log/virlink/<name>.log` | per-tunnel logs |
| `/var/run/virlink/<name>.pid` | PID files |
| `/usr/local/bin/virlink` | symlink → binary |
| `/usr/local/bin/virlink-setup` | symlink → setup.sh |

---

## Releasing

Every GitHub release must include **both** assets so the install one-liner works:

| Asset | URL |
|-------|-----|
| `setup.sh` | `https://github.com/hosseinpv1379/virtlink/releases/latest/download/setup.sh` |
| `virlink` | `https://github.com/hosseinpv1379/virtlink/releases/latest/download/virlink` |

From the `virlink/` directory (after bumping `main.go` version):

```bash
./release.sh vX.Y.Z "Release notes"
```

Verify:

```bash
curl -fsSL -I https://github.com/hosseinpv1379/virtlink/releases/latest/download/setup.sh
curl -fsSL -I https://github.com/hosseinpv1379/virtlink/releases/latest/download/virlink
```

---

## License

MIT
