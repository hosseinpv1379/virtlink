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
