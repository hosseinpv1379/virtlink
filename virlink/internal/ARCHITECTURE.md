# virlink internal layout

Layered structure — edit one protocol without touching others.

```
internal/
├── core/           Tunnel interface, type registry, overlay IP helpers
├── config/         TOML types, load, defaults (uses core.MetaFor)
├── app/            CLI entry, daemon lifecycle
├── platform/       Shared runtime: TUN, poll, pools, perf, tuning, health, UI, netlink
├── wire/           Wire spoofing (raw IP, nftables mangle, TCP route)
└── protocol/       One package per tunnel type — each registers in init()
    ├── register.go   blank-imports all protocol packages
    ├── icmp/
    ├── udp/
    ├── tcp/
    ├── tcpmux/
    ├── bip/
    ├── udpobfs/
    ├── kernel/       gre-fou, ipip-fou, bonded, l2tpv3, ipsec, gre
    ├── openvpn/
    ├── openvpnmultu/
    ├── hysteria2/
    ├── wireguard/
    └── amneziawg/
```

## Dependency rules

```
app  →  core, config, platform, protocol/register
protocol/*  →  core, config, platform, wire (when needed)
platform  →  core, config, wire
wire  →  config
config  →  core
core  →  config (factory signature only)
```

## Adding a new tunnel type

1. Create `internal/protocol/mytunnel/tunnel.go`
2. Implement `core.Tunnel`
3. In `init()`: `core.Register("mytunnel", core.Meta{...}, factory)`
4. Add blank import in `protocol/register.go`

No changes to `app/` or giant switch statements.

## Editing one protocol

Work in `internal/protocol/<name>/` — no imports from other protocol packages.

**See [EDITING.md](./EDITING.md)** for a full “what files to touch” guide (UDP example, scenarios, checklist).
