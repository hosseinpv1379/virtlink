# Editing Guide — Which Files to Touch

Use this document when asking an AI (or a human) to change **one protocol or one concern** in virlink. It defines **scope**: what to edit, what to leave alone, and how layers connect.

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the high-level layout.

---

## Golden rule

| Layer | Path | Role |
|-------|------|------|
| **Protocol** | `internal/protocol/<name>/` | Tunnel logic — **start here** |
| **Core** | `internal/core/` | `Tunnel` interface, type registry, overlay IP helpers |
| **Config** | `internal/config/` | TOML types, `Load()`, defaults |
| **Platform** | `internal/platform/` | Shared runtime: TUN, perf, tuning, health, UI, netlink |
| **Wire** | `internal/wire/` | Wire spoof / raw IP / mangle |
| **App** | `internal/app/` | CLI + daemon — rarely needed for protocol work |

**~90% of protocol changes** stay inside `internal/protocol/<name>/`.

**Do not** add giant `switch cfg.Tunnel.Type` blocks. Types register via `core.Register()` in each protocol’s `register.go`.

---

## Protocol home directories

| `[tunnel] type` | Edit here |
|-----------------|-----------|
| `udp` | `internal/protocol/udp/` |
| `icmp` | `internal/protocol/icmp/` |
| `tcp` | `internal/protocol/tcp/` |
| `tcpmux` | `internal/protocol/tcpmux/` |
| `bip` | `internal/protocol/bip/` |
| `udp-obfs` | `internal/protocol/udpobfs/` |
| `gre-fou`, `ipip-fou`, `bonded-gre-fou`, `l2tpv3`, `gre-fou-ipsec`, `gre` | `internal/protocol/kernel/` (one file per type, e.g. `tun_gre_fou.go`) |
| `openvpn` | `internal/protocol/openvpn/` |
| `openvpnmultu` | `internal/protocol/openvpnmultu/` + `internal/platform/openvpnmultu_*.go` |
| `hysteria2` | `internal/protocol/hysteria2/` |
| `wireguard` | `internal/protocol/wireguard/` |
| `amneziawg` | `internal/protocol/amneziawg/` |

---

## Example: edit UDP

**Home folder:**

```
internal/protocol/udp/
├── udp.go        ← main logic (Up/Down/RX/TX/Status)
└── register.go   ← core.Register("udp", Meta{…}, factory)
```

### File scope for UDP

| File | When to edit |
|------|--------------|
| **`protocol/udp/udp.go`** | RX/TX loops, sockets, batching, wire path, Status, Down, overlay subnet constant |
| **`protocol/udp/register.go`** | `DefaultMTU`, `DefaultPort`, `Meta` flags (`Userspace`, etc.) |
| **`protocol/register.go`** | Only when **adding/removing** a protocol package (UDP already imported) |
| **`core/registry.go`** | **No** — no central switch; UDP registers in `init()` |
| **`app/cli.go`** | Only if `--help` text changes (e.g. default port 5060) |
| **`config/config.go`** | Only when adding a **new TOML field** for UDP |
| **`platform/perf.go`** | UDP-specific perf defaults (`batch_size`, `sock_buf`, …) — see `case "udp"` |
| **`platform/tuning.go`** | Shared userspace sysctl tuning (not UDP-only logic) |
| **`platform/tundev.go`**, **`tun_poll.go`**, **`batch_linux.go`**, **`pool.go`** | Shared TUN bugs/improvements — **not** UDP business logic |
| **`wire/spoof.go`**, **`wire/wire_ip.go`** | `[mangle]` wire spoof for UDP (`BuildWireUDP`, `AcceptWirePeer`, …) |
| **`wire/mangle_kernel.go`** | **No** for userspace UDP — kernel tunnels only |
| **`configs/**/udp.toml`** | Sample configs for test/deploy |
| **`scripts/setup.sh`** | Installer menu / TOML templates for UDP |
| **`test/harness.go`** | Integration test harness entry for `udp` |

### UDP imports

```
udp.go  →  core      (OverlayAddr, PeerAddr)
        →  config    (*config.Config)
        →  platform  (TUN, perf, tuning, stats, logging, MSS, lock, …)
        →  wire      (WireSpoof, BuildWireUDP, raw socket — when [mangle] enabled)
```

**“Change UDP logic”** → edit **`udp.go`** only (sometimes **`register.go`**).

---

## Scenario → files (any protocol; UDP as example)

Legend: **MUST** = expected edits · **MAY** = related · **DO NOT** = out of scope

### 1. Tunnel logic (RX/TX, reconnect, port handling, …)

| Scope | Path |
|-------|------|
| **MUST** | `internal/protocol/udp/udp.go` |
| **DO NOT** | Other protocols (`tcp/`, `icmp/`, …), `app/`, `core/` (unless `Tunnel` interface changes) |

### 2. Default MTU or port

| Scope | Path |
|-------|------|
| **MUST** | `internal/protocol/udp/register.go` (`Meta.DefaultMTU`, `Meta.DefaultPort`) |
| **MAY** | `internal/app/cli.go` (help text), `configs/**/udp.toml`, `scripts/setup.sh` |

### 3. Overlay subnet (e.g. `10.20.42.0/24`)

| Scope | Path |
|-------|------|
| **MUST** | `internal/protocol/udp/udp.go` (e.g. `udpRawSubnet` constant) |
| **MAY** | `configs/**/udp.toml` (`[tunnel] cidr`) |
| **DO NOT** | `core/overlay.go` — fallback subnet lives **in the protocol file** |

### 4. New config.toml field (e.g. `[udp] timeout = 30`)

| Scope | Path |
|-------|------|
| **MUST** | `internal/config/config.go` (struct + defaults + validate) |
| **MUST** | `internal/protocol/udp/udp.go` (read the field) |
| **MAY** | `configs/**/udp.toml`, `scripts/setup.sh` |

### 5. Perf / batch / tun_queues defaults

| Scope | Path |
|-------|------|
| **MUST** | `internal/platform/perf.go` (`case "udp"` in `initUserspacePerfDefaults`) |
| **MAY** | `internal/protocol/udp/register.go` (`Meta.Userspace` affects perf path) |
| **DO NOT** | `udp.go` unless changing UDP’s own batching logic |

UDP and BIP share perf grouping (`batch_size = 64`).

### 6. Wire spoof (`[mangle] srcip` / `dstip`)

| Scope | Path |
|-------|------|
| **MUST** | `internal/protocol/udp/udp.go` (raw vs normal UDP path) |
| **MUST** | `internal/wire/spoof.go` (allowed tunnel types list) |
| **MUST** | `internal/wire/wire_ip.go` (`BuildWireUDP`, parse, `AcceptWirePeer`) |
| **MAY** | `configs/spooftest/**/udp.toml` |
| **DO NOT** | `internal/wire/mangle_kernel.go` (kernel tunnels only) |

### 7. Stats / profiler (`/profile`)

| Scope | Path |
|-------|------|
| **MUST** | `internal/protocol/udp/udp.go` (`StatInc(StatUDPRx…)`, etc.) |
| **MAY** | `internal/platform/stats.go` (new counter), `internal/platform/ui.go` (dashboard) |

### 8. Health / heartbeat / dashboard

| Scope | Path |
|-------|------|
| **MAY** | `internal/platform/health.go`, `internal/app/daemon.go` |
| **DO NOT** | `udp.go` unless UDP-specific heartbeat is required |

### 9. Shared TUN bug (write=0, queues, EAGAIN)

| Scope | Path |
|-------|------|
| **MUST** | `internal/platform/tundev.go`, `tun_poll.go`, `batch_linux.go` |
| **DO NOT** | `udp.go` except a temporary workaround |

---

## Add a new tunnel type

1. `internal/protocol/mytunnel/tunnel.go` — implement `core.Tunnel`
2. `internal/protocol/mytunnel/register.go` — `core.Register("mytunnel", Meta{…}, factory)`
3. `internal/protocol/register.go` — `_ "virlink/internal/protocol/mytunnel"`
4. `configs/examples/mytunnel/…` — sample TOML
5. **Optional:** `app/cli.go` help, `scripts/setup.sh`, `test/harness.go`

No changes to a central switch in `app/` or `core/registry.go`.

---

## Pre-PR checklist

- [ ] Only the target protocol folder + **MAY** files were touched
- [ ] `GOOS=linux go build ./...` passes
- [ ] If `Meta` or config changed, sample TOML updated
- [ ] No cross-protocol imports (e.g. `tcp` must not import `udp`)

---

## One-liner

> **“Edit UDP”** ≈ `internal/protocol/udp/udp.go` (+ sometimes `register.go`).  
> Touch `platform/` for shared TUN/perf; `wire/` for mangle; `app/` for CLI/help only.

---

## Instructions for AI agents

When you receive a task about virlink:

1. **Identify the tunnel type** from the user message or config (`[tunnel] type = "udp"` → `internal/protocol/udp/`).
2. **Classify the change** using the scenario table above (logic / config / perf / wire / TUN / stats).
3. **Edit the smallest set of files** — prefer **MUST** only; add **MAY** if the user asked for docs, samples, or installer updates.
4. **Do not refactor unrelated protocols** or shared platform code unless the scenario requires it.
5. **Preserve behavior** unless the user explicitly asks for a behavior change.
6. **Register new types** via `register.go` + `protocol/register.go`; never add a large type switch.
7. **Verify** with `GOOS=linux go build ./...` (Linux-only project).

---

## Sample prompt (copy, fill in, append to your message)

Attach or reference this file (`internal/EDITING.md`) and paste:

```text
You are editing the virlink repo (Linux tunnel manager, Go).

Read internal/EDITING.md and internal/ARCHITECTURE.md first.
Follow the file scope rules: edit only MUST files unless I say otherwise.
Do not touch other protocols. No giant switch statements.

Tunnel type: udp
Scope: protocol logic only (unless scenario needs platform/wire/config)

Problem:
<describe the bug — symptoms, logs, when it happens>

Add feature:
<what you want added or changed — be specific>

Constraints:
- Minimal diff; match existing style
- GOOS=linux go build ./... must pass
- Do not commit unless I ask

Files you plan to edit (list before coding):
1.
2.
```

### Shorter variant

```text
@internal/EDITING.md

Tunnel: tcp
Problem: ping works one way only; server logs show tx=0
Add feature: retry TUN write on EAGAIN without dropping packets

Edit only protocol/tcp/ unless TUN layer is clearly broken.
List files first, then implement.
```

### Field reference

| Field | Purpose |
|-------|---------|
| **Tunnel type** | Maps to `internal/protocol/<name>/` |
| **Problem** | Bug context — helps AI avoid wrong layer (protocol vs platform) |
| **Add feature** | Desired outcome — concrete, testable |
| **Constraints** | Build target, no commit, minimal scope, etc. |
| **Files you plan to edit** | Forces AI to justify scope before coding |

---

## Example filled prompt (UDP)

```text
@internal/EDITING.md

Tunnel type: udp
Scope: protocol logic + wire if needed

Problem:
Client connects (hs=connected) but ping to peer overlay fails.
Logs: RX wire recv > 0, tun write = 0 on server.

Add feature:
Fix server RX path so packets reach TUN; do not change client behavior.

Constraints:
- Minimal diff
- GOOS=linux go build ./... must pass
- Do not edit tcp/, icmp/, or platform/tundev.go unless you prove TUN is the root cause

Files you plan to edit (list before coding):
1. internal/protocol/udp/udp.go
2. (only if mangle path) internal/wire/wire_ip.go
```
