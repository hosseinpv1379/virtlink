# virlink

**Kernel-native virtual tunnel manager** — GRE, IPIP, L2TP, IPsec, obfuscated UDP, raw ICMP/TCP/UDP/BIP tunnels, all managed through a single binary and interactive setup script.

[![Release](https://img.shields.io/github/v/release/hosseinpv1379/virtlink-install)](https://github.com/hosseinpv1379/virtlink-install/releases/latest)
[![Platform](https://img.shields.io/badge/platform-linux%20amd64-blue)](https://github.com/hosseinpv1379/virtlink-install/releases/latest)

> **Source code is private.** This document is for developers with repo access.
> Public installs use the [virtlink-install](https://github.com/hosseinpv1379/virtlink-install) release repo only.

---

## Quick Start (public install)

```bash
# Install (as root)
sudo bash <(curl -fsSL https://github.com/hosseinpv1379/virtlink-install/releases/latest/download/setup.sh)
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
| `udp-obfs` | UDP | AES-256-GCM + fake headers | ✓ | **DPI bypass / Iran** |
| `gre-fou-ipsec` | UDP | GRE-FOU + IPsec ESP | ✓ | Encrypted FOU |
| `gre` | IP/47 | Plain kernel GRE | ✗ | No UDP wrapper |
| `tcp` | TCP | User-space TCP tunnel | ✗ | Firewall-friendly |
| `udp` | UDP | User-space plain UDP | ✗ | Simple UDP transport |
| `icmp` | IP/1 | ICMP Echo carrier | ✗ | DPI evasion |
| `bip` | IP/58 | Proto-58 carrier (ICMPv6 number) | ✗ | DPI evasion |
| `openvpn` | UDP/TCP | OpenVPN core site-to-site | ✓ | Encrypted link · UDP=max BW |

---

## Learn: OpenVPN tunnel

virlink does **not** reimplement OpenVPN. It wraps the system **`openvpn`** binary: generates PKI and configs, starts/stops the daemon, waits for the TUN device, applies kernel tuning, and tears everything down on exit. Encryption and the data plane are handled entirely by OpenVPN.

```
┌─────────────┐     UDP/TCP (1194)      ┌─────────────┐
│   Server    │ ◄──────────────────────► │   Client    │
│  virlink    │      OpenVPN core        │  virlink    │
│     │       │                          │     │       │
│ ovpn-tun0   │    overlay 10.x.0.0/24   │ ovpn-tun0   │
│  .2 (srv)   │ ◄──── ping / routes ───► │  .1 (cli)   │
└─────────────┘                          └─────────────┘
```

### When to use it

| Choose | When |
|--------|------|
| **UDP** (default) | Maximum bandwidth; both sides can reach each other on a UDP port |
| **TCP** | Strict firewalls that block UDP; slightly lower throughput |
| **fast** profile | Default — highest throughput |
| **resource** profile | Lower CPU wakeups / power use |
| **latency** profile | Minimal delay |

Other tunnel types (GRE, icmp, udp-obfs) are better for raw speed or DPI evasion without TLS overhead. OpenVPN is the right choice when you need **standard encrypted site-to-site** with minimal manual PKI work.

### Prerequisites

- Linux amd64, **root**
- **`openvpn`** and **`openssl`** — installed automatically by `virlink-setup` on install, update, and when creating/starting OpenVPN tunnels (apt/dnf/yum/apk/zypper; EPEL on RHEL)
- For automated PKI sync: **passwordless SSH** from client → server (`ssh-copy-id root@SERVER_IP`)

### Step-by-step (interactive)

**1. Install virlink on both servers**

```bash
sudo bash <(curl -fsSL https://github.com/hosseinpv1379/virtlink/releases/latest/download/setup.sh)
```

**2. Server (Kharej / listener side)**

```bash
sudo virlink-setup
# 1) Create tunnel config
#    → client/server: server
#    → category: userspace
#    → type: openvpn
#    → same tunnel name on both sides (e.g. site1)
#    → transport: udp (or tcp)
#    → profile: fast
```

Setup will:

- Generate **ECDSA P-256** PKI under `/opt/virlink/pki/<name>/`
- Write `server.conf` with **tls-crypt** (no legacy `tls-auth`)
- Create a **client-only export** at `/opt/virlink/pki/<name>/export/` (no CA or server private keys)
- Offer to **push credentials to the client via SSH**

**3. Client (Iran / initiator side)**

```bash
sudo virlink-setup
# 1) Create tunnel config
#    → client/server: client
#    → same tunnel name and overlay CIDR as server
#    → peer IP = server's public IP
```

If PKI is not present locally, setup **auto-fetches** the client bundle from the server over SSH (certs + tls-crypt only).

**4. Start the tunnel**

```bash
sudo virlink-setup   # option 2) Start tunnel
# or
sudo virlink -c /opt/virlink/configs/<name>.toml up
```

**5. Test overlay**

```bash
# from client
ping -c3 10.99.0.2

# from server
ping -c3 10.99.0.1
```

Overlay addressing convention: **client = `.1`**, **server = `.2`** in the chosen CIDR (e.g. `10.99.0.0/24`).

### Privacy model

| Stays on server only | Sent to client |
|----------------------|----------------|
| `ca.key`, `server.key`, `server.crt`, `dh.pem` (if legacy) | `ca.crt`, `client.crt`, `client.key`, `tc.key` |

- **tls-crypt** encrypts the control channel (better than old `tls-auth`)
- **ECDH** (`dh none` + `ecdh-curve prime256v1`) — no static DH file on new PKI
- If server-only files land on the client, setup **strips them automatically**

### File locations

| Path | Purpose |
|------|---------|
| `/opt/virlink/pki/<name>/server.conf` | OpenVPN server config |
| `/opt/virlink/pki/<name>/client.conf` | OpenVPN client config |
| `/opt/virlink/pki/<name>/export/` | Client-safe credential bundle |
| `/opt/virlink/configs/<name>.toml` | virlink tunnel config |
| `/var/log/virlink/<name>-openvpn.log` | OpenVPN daemon log |

Example configs: `configs/examples/openvpn/server/config.toml` and `configs/examples/openvpn/client/config.toml`.

### Manual / advanced

```toml
[tunnel]
type = "openvpn"
mode = "server"          # or "client"
cidr = "10.99.0.0/24"
mtu  = 1472              # 1472 UDP · 1400 TCP

[transport]
port  = 1194
proto = "udp"            # or "tcp"

[openvpn]
config = "/opt/virlink/pki/site1/server.conf"
dev    = "ovpn-tun0"

[tuning]
mode = "fast"            # fast | resource | latency
```

Wire IP spoof (`[mangle]`) is **not supported** for OpenVPN tunnels.

### Troubleshooting

| Problem | Fix |
|---------|-----|
| `'openvpn' not found` | Re-run setup — deps install automatically as root |
| PKI fetch fails | Run server setup first; ensure `ssh root@SERVER` works without a password |
| Tunnel up but no ping | Open firewall: `proto/port` between public IPs; check overlay IPs |
| Old PKI (`ta.key` / `dh.pem`) | Re-run server setup to regenerate export, or migrate configs manually |

---

## Interactive Menu

```
sudo virlink-setup

  1) Create tunnel config
  2) Start tunnel
  3) Stop tunnel
  4) Status
  5) Update virlink
  6) Uninstall
```

---

## Project layout

```
virlink/
├── cmd/virlink/           CLI entry (thin main)
├── internal/virlink/      all tunnel + runtime logic (see doc.go)
├── configs/
│   ├── examples/          sample config.toml per tunnel type
│   └── spooftest/       manual wire-spoof test configs
├── scripts/
│   ├── setup.sh           interactive installer / manager
│   └── release.sh         publish binary + setup.sh to GitHub
├── test/                  integration harness (separate go.mod)
├── Makefile
└── go.mod
```

See `internal/virlink/doc.go` for the full source file map.

---

## Releasing

Releases go to the **public install repo** (`virtlink-install`), not this source repo.
Every release must include **both** assets so the install one-liner works:

| Asset | URL |
|-------|-----|
| `setup.sh` | `https://github.com/hosseinpv1379/virtlink-install/releases/latest/download/setup.sh` |
| `virlink` | `https://github.com/hosseinpv1379/virtlink-install/releases/latest/download/virlink` |

From the `virlink/` directory (after bumping version in `internal/virlink/cli.go`):

```bash
./scripts/release.sh vX.Y.Z "Release notes"
```

Verify:

```bash
curl -fsSL -I https://github.com/hosseinpv1379/virtlink-install/releases/latest/download/setup.sh
curl -fsSL -I https://github.com/hosseinpv1379/virtlink-install/releases/latest/download/virlink
```

---

## License

MIT
