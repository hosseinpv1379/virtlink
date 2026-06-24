# virlink-test — Benchmark & Validation Suite

A standalone binary for bidirectional protocol benchmarking and validation of
[virlink](https://github.com/hosseinpv1379/virtlink) tunnels.

> **Does not modify virlink in any way.**  
> Download it separately from the Releases page and run it alongside your tunnels.

---

## Download

```bash
# Download to current directory
curl -fsSL -O https://github.com/hosseinpv1379/virtlink/releases/latest/download/virlink-test
chmod +x virlink-test
```

---

## How It Works

```
Host A (local)                          Host B (remote)
──────────────────────                  ──────────────────────
virlink -c server.toml   ◄──tunnel──►  virlink -c client.toml
         :6543/health                            :6543/health
         :6544/bench                             :6544/bench
         │
         └── virlink-test (coordinator)
               1. waits for handshake=connected
               2. runs /bench  (↓ download, ↑ upload)
               3. runs ping    (p50/p95/p99 latency)
               4. reads /proc  (CPU%, RSS MiB)
               5. prints table + writes JSON report
```

`virlink-test` supports **three backends**:

| Backend | Description |
|---------|-------------|
| `local` | Spawns two virlink processes on the same machine (needs two IPs) |
| `ssh`   | Runs side A locally, starts side B via SSH on a remote host |
| `api`   | Connects to already-running virlink instances via their HTTP API |

---

## Quick Start

### 1. API-only mode  *(virlink already running on both hosts)*

This is the easiest way to test.  Start your tunnels normally on both hosts,
then run:

```bash
# On Host A (e.g. 81.12.35.242), after tunnel is UP:
./virlink-test \
  --backend   api \
  --overlay-a 10.20.10.1 \
  --overlay-b 10.20.10.2 \
  --health-port 6543
```

Expected output:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ⬡  virlink-test v1.0.0  ·  protocol benchmark suite
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  host A    10.20.10.1   (local)
  host B    10.20.10.2   (api-only)
  overlay   10.20.10.0/30
  backend   api

  protocols   gre-fou  ipip-fou  bonded-gre-fou  l2tpv3  ...

  ────────────────────────────────────────────────────────────────────────────────────────────────
  PROTOCOL              DIR    STATUS    ↓ DOWNLOAD     ↑ UPLOAD   p50 lat  LOSS  CPU   MEM
  ────────────────────────────────────────────────────────────────────────────────────────────────
  gre-fou               A→B    ✓ pass   842.3 Mbps   811.7 Mbps   0.82ms   0.0%   8%   12M
  gre-fou               B→A    ✓ pass   837.1 Mbps   799.4 Mbps   0.91ms   0.0%   7%   12M
  ipip-fou              A→B    ✓ pass   920.1 Mbps   905.3 Mbps   0.70ms   0.0%   6%   11M
  udp-obfs              A→B    ✓ pass   280.4 Mbps   265.1 Mbps   1.21ms   0.0%  31%   14M
  tcp                   A→B    ✗ FAIL   —            —            —        —
    ↳ not connected: tunnel not connected (status="waiting") after 30s
  ────────────────────────────────────────────────────────────────────────────────────────────────
  total=14  pass=12  fail=2  skip=0

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Recommendations

  ✓  gre-fou             ✓ production-ready — 827 Mbps avg, 0.8 ms p50
  ✓  ipip-fou            ✓ production-ready — 912 Mbps avg, 0.7 ms p50
  ○  udp-obfs            ○ moderate — 272 Mbps avg; tune socket buffers
  ✗  tcp                 not recommended — test failed: not connected
```

---

### 2. SSH mode  *(automated two-machine testing)*

Requires:
- `virlink` binary on **both** hosts at the same path
- SSH key access from Host A to Host B
- Root on both hosts

```bash
sudo ./virlink-test \
  --backend    ssh \
  --host-a     81.12.35.242 \
  --host-b     5.75.206.15 \
  --ssh-user   root \
  --ssh-key    ~/.ssh/id_ed25519 \
  --overlay    10.99.0.0/30 \
  --virlink-bin /opt/virlink/virlink \
  --remote-bin  /opt/virlink/virlink
```

virlink-test will:
1. Generate TOML configs for both hosts automatically
2. Start virlink on Host A (local)
3. Upload config + start virlink on Host B via SSH
4. Wait for the tunnel to come up (max `--warmup`, default 30s)
5. Run throughput, latency, and resource tests
6. Tear down both sides after each test

---

### 3. Local mode  *(single machine, two processes)*

Useful for development testing.  Requires two IP addresses on the same host
(e.g., `127.0.0.1` and `127.0.0.2`).  On Linux you can add a second loopback
address with:

```bash
sudo ip addr add 127.0.0.2/8 dev lo
```

Then run:

```bash
sudo ./virlink-test \
  --backend   local \
  --host-a    127.0.0.1 \
  --host-b    127.0.0.2 \
  --overlay   10.99.0.0/30 \
  --virlink-bin /opt/virlink/virlink \
  --only gre-fou,udp-obfs,tcp
```

> Note: Kernel tunnels (GRE, IPIP, etc.) share the same namespace in local
> mode and may conflict.  Use `--only` to test user-space protocols (tcp, udp,
> icmp, bip, udp-obfs) for reliable local testing.

---

## All Flags

```
  --host-a          IP of local (coordinator) host          [auto-detected]
  --host-b          IP of remote/peer host                  [required for ssh]
  --ssh-user        SSH username for host B                 [root]
  --ssh-key         SSH private key path for host B         []
  --ssh-port        SSH port for host B                     [22]
  --remote-bin      virlink binary path on host B           [/opt/virlink/virlink]

  --backend         local | ssh | api                       [local]
  --overlay         overlay CIDR  (A gets .1, B gets .2)    [10.99.0.0/30]
  --overlay-a       host A overlay IP  (api mode only)      []
  --overlay-b       host B overlay IP  (api mode only)      []
  --health-port     virlink health/bench port               [6543]
  --virlink-bin     local virlink binary                    [/opt/virlink/virlink]

  --only            comma-separated protocols to test       [all]
  --bidirect        run both A→B and B→A directions         [true]
  --warmup          max time to wait for tunnel up          [30s]
  --pings           ping count per latency test             [30]
  --verbose         print per-step debug output             [false]
  --json            write JSON report to file               []
```

---

## Protocol Coverage

| Protocol | Type | Notes |
|----------|------|-------|
| `gre-fou` | Kernel GRE-in-UDP | Best throughput, production-ready |
| `ipip-fou` | Kernel IPIP-in-UDP | Lowest overhead |
| `bonded-gre-fou` | Dual GRE-FOU ECMP | 2× bandwidth bonding |
| `l2tpv3` | Kernel L2TPv3/UDP | L2 bridging capable |
| `gre` | Raw GRE proto 47 | No port, simple |
| `udp-obfs` | User-space AES-256-GCM | DPI evasion (Iran) |
| `tcp` | User-space TCP | Firewall-friendly |
| `udp` | User-space UDP | Low-overhead user-space |
| `icmp` | ICMP Echo tunnel | For very restricted networks |
| `bip` | Proto 58 (ICMPv6) | Alternative raw tunnel |

---

## JSON Report

Pass `--json report.json` to save a machine-readable report:

```json
{
  "version": "1.0.0",
  "tested_at": "2026-06-24T19:10:01Z",
  "host_a": "81.12.35.242",
  "host_b": "5.75.206.15",
  "overlay_cidr": "10.99.0.0/30",
  "results": [
    {
      "protocol": "gre-fou",
      "label": "GRE-in-UDP (FOU)",
      "direction": "A→B",
      "status": "pass",
      "download_mbps": 842.3,
      "upload_mbps": 811.7,
      "latency_p50_ms": 0.82,
      "latency_p95_ms": 1.10,
      "latency_p99_ms": 1.43,
      "loss_pct": 0,
      "client_cpu_pct": 8,
      "client_mem_mib": 12,
      "recommendation": "✓ production-ready — 827 Mbps avg, 0.8 ms p50",
      "duration_ms": 28000000000,
      "tested_at": "2026-06-24T19:10:01Z"
    }
  ],
  "summary": {
    "total": 14,
    "pass": 12,
    "fail": 2,
    "skipped": 0
  }
}
```

---

## CI/CD Integration

`virlink-test` exits with code **1** if any test fails, making it CI-friendly:

```yaml
# GitHub Actions example
- name: Run tunnel benchmarks
  run: |
    ./virlink-test \
      --backend api \
      --overlay-a ${{ secrets.OVERLAY_A }} \
      --overlay-b ${{ secrets.OVERLAY_B }} \
      --only gre-fou,udp-obfs \
      --json bench-report.json

- name: Upload report
  uses: actions/upload-artifact@v4
  with:
    name: bench-report
    path: bench-report.json
```

---

## Build from Source

```bash
git clone https://github.com/hosseinpv1379/virtlink --branch source
cd virtlink/virlink/test
go build -o virlink-test .

# cross-compile for Linux
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o virlink-test .
```

Requires Go 1.21+.  No external dependencies.
