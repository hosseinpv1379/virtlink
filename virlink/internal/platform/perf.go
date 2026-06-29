// perf.go — runtime performance knobs from [tuning] in config.toml.
package platform

import (
	"virlink/internal/wire"
	"virlink/internal/config"
	"fmt"
	"runtime"
)

const (
	MaxPerfQueues = 16
	maxPerfBatch  = 128

	defSockBufMB = 32
	defTunQueues = 4
	defBatchSize = 32
	defTxQLen    = 10000
	defPollMs    = 10
)

type perfRuntime struct {
	sockBuf    int
	tunQueues  int
	batchSize  int
	txQLen     int
	pollMs     int
	tcpStreams int
}

var perf perfRuntime

func init() {
	initPerfDefaults()
}

func initPerfDefaults() {
	ncpu := runtime.NumCPU()
	if ncpu > defTunQueues {
		ncpu = defTunQueues
	}
	if ncpu < 1 {
		ncpu = 1
	}
	perf = perfRuntime{
		sockBuf:    defSockBufMB << 20,
		tunQueues:  ncpu,
		batchSize:  defBatchSize,
		txQLen:     defTxQLen,
		pollMs:     defPollMs,
		tcpStreams: ncpu,
	}
}

func isUserspaceTunnel(typ string) bool {
	switch typ {
	case "icmp", "udp", "tcp", "tcpmux", "bip", "udp-obfs", "openvpn", "openvpnmultu", "hysteria2", "wireguard", "amneziawg":
		return true
	}
	return false
}

func isTcpUserspaceTunnel(typ string) bool {
	return typ == "tcp" || typ == "tcpmux"
}

// userspaceCPU caps parallelism for userspace tunnels (TUN pollers + TCP streams).
func userspaceCPU() int {
	return clampInt(runtime.NumCPU(), 1, 8)
}

// userspaceQueues — multi-queue TUN lets the kernel spread stack→TUN traffic across fds.
func userspaceQueues() int {
	return clampInt(userspaceCPU(), 2, MaxPerfQueues)
}

// userspaceTcpStreams — parallel TCP conns for tcp/tcpmux (independent of tun_queues).
func userspaceTcpStreams() int {
	return clampInt(userspaceCPU(), 4, MaxPerfQueues)
}

// initUserspacePerfDefaults picks per-protocol defaults tuned for throughput on Linux.
func initUserspacePerfDefaults(c *config.Config) {
	queues := userspaceQueues()
	streams := userspaceTcpStreams()

	perf = perfRuntime{
		sockBuf:    64 << 20,
		tunQueues:  queues,
		batchSize:  defBatchSize,
		txQLen:     defTxQLen,
		pollMs:     10, // 10ms idle poll — good CPU/bandwidth balance; wire boost can lower
		tcpStreams: streams,
	}

	switch c.Tunnel.Type {
	case "icmp":
		perf.batchSize = 64
	case "udp", "bip":
		// Match ICMP batch size — sendmmsg is equally effective here.
		perf.batchSize = 64
	case "tcp", "tcpmux":
		// Wire socket buffer deliberately smaller than other protocols:
		// large buffers cause TCP-over-TCP bufferbloat (inner TCP sees inflated
		// RTT equal to buffer_size / wire_bandwidth, triggering mass retransmits).
		// TCP_NOTSENT_LOWAT (256 KB, set in tuneTCPConnForce) enforces the real
		// limit; this 8 MB value covers in-flight BDP for fast links while keeping
		// the kernel queue bounded.
		perf.sockBuf = 8 << 20
		// 3 ms poll keeps latency low while batching consecutive packets efficiently.
		perf.pollMs = 3
	case "udp-obfs":
		perf.sockBuf = 32 << 20
		perf.tunQueues = clampInt(userspaceCPU(), 2, 4)
		perf.batchSize = 64
		perf.pollMs = 10
	case "openvpn", "openvpnmultu":
		perf.tunQueues = 1
		perf.sockBuf = defSockBufMB << 20
		perf.tcpStreams = 1
		switch tuningMode(c) {
		case tuningResource:
			perf.pollMs = 100
		case tuningLatency:
			perf.pollMs = 20
		default:
			perf.pollMs = 50
		}
	case "hysteria2":
		// Wrap path is loopback UDP — low latency, use smaller poll interval.
		// More queues let the kernel spread TUN→wire traffic.
		perf.tunQueues = clampInt(userspaceCPU(), 2, 4)
		perf.sockBuf = 64 << 20
		perf.batchSize = 64
		perf.pollMs = 10
	case "wireguard", "amneziawg":
		perf.tunQueues = 1
		perf.sockBuf = defSockBufMB << 20
		perf.tcpStreams = 1
		perf.pollMs = 50
	}

	if tuningMode(c) == tuningResource {
		perf.sockBuf = 16 << 20
		perf.tunQueues = 1
		perf.batchSize = 16
		perf.pollMs = 20
		if isTcpUserspaceTunnel(c.Tunnel.Type) {
			perf.tcpStreams = 2
		} else {
			perf.tcpStreams = 1
		}
	}
}

// applyPerfFromConfig loads [tuning] performance fields (0 = default for that field).
func ApplyPerfFromConfig(c *config.Config) {
	t := &c.Tuning
	if isUserspaceTunnel(c.Tunnel.Type) {
		initUserspacePerfDefaults(c)
	} else {
		initPerfDefaults()
	}

	if t.SockBufMB > 0 {
		perf.sockBuf = clampInt(t.SockBufMB, 1, 128) << 20
	}
	if t.TunQueues > 0 {
		perf.tunQueues = clampInt(t.TunQueues, 1, MaxPerfQueues)
	}
	if t.BatchSize > 0 {
		perf.batchSize = clampInt(t.BatchSize, 1, maxPerfBatch)
	}
	if t.PollMs > 0 {
		perf.pollMs = clampInt(t.PollMs, 1, 1000)
	}
	if t.TcpStreams > 0 {
		perf.tcpStreams = clampInt(t.TcpStreams, 1, MaxPerfQueues)
	} else if !isTcpUserspaceTunnel(c.Tunnel.Type) {
		// Non-TCP tunnels ignore tcp_streams; do not clobber protocol defaults.
		perf.tcpStreams = perf.tunQueues
	}

	if t.TxQLen > 0 {
		perf.txQLen = clampInt(t.TxQLen, 100, 100000)
	} else {
		switch tuningMode(c) {
		case tuningFast:
			perf.txQLen = 10000
		case tuningResource:
			perf.txQLen = 2000
		case tuningLatency:
			perf.txQLen = 5000
		}
	}

	// When only tun_queues is raised for tcp/tcpmux, scale streams to match unless set explicitly.
	if isTcpUserspaceTunnel(c.Tunnel.Type) && t.TcpStreams == 0 && t.TunQueues > 0 &&
		perf.tcpStreams < perf.tunQueues {
		perf.tcpStreams = perf.tunQueues
	}

	applyWirePerfBoost(c)
}

// applyWirePerfBoost raises throughput defaults when [mangle] wire relay is active.
func applyWirePerfBoost(c *config.Config) {
	if !wire.WireSpoofEnabled(c) {
		return
	}
	perf.sockBuf = maxInt(perf.sockBuf, 64<<20)
	switch c.Tunnel.Type {
	case "tcp", "tcpmux":
		n := clampInt(userspaceCPU(), 4, MaxPerfQueues)
		perf.tcpStreams = maxInt(perf.tcpStreams, n)
		perf.tunQueues = maxInt(perf.tunQueues, n)
		perf.pollMs = minInt(perf.pollMs, 2)
		perf.batchSize = maxInt(perf.batchSize, 32)
	case "icmp":
		perf.tunQueues = maxInt(perf.tunQueues, userspaceQueues())
		perf.batchSize = maxInt(perf.batchSize, 64)
		perf.pollMs = minInt(perf.pollMs, 5)
	case "udp", "bip":
		perf.tunQueues = maxInt(perf.tunQueues, userspaceQueues())
		perf.batchSize = maxInt(perf.batchSize, 32)
		perf.pollMs = minInt(perf.pollMs, 5)
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func PerfSockBuf() int       { return perf.sockBuf }
func PerfTunQueues() int     { return perf.tunQueues }
func PerfBatchSize() int     { return perf.batchSize }
func perfTxQLen() int         { return perf.txQLen }
func PerfPollMs() int         { return perf.pollMs }
func PerfTcpStreams() int     { return perf.tcpStreams }

// perfIdleCapMs is the max adaptive idle poll backoff (TX poller + wire RX loops).
func perfIdleCapMs() int {
	if perf.pollMs >= 20 {
		return 200
	}
	return 100
}

// idleBackoff increases idle poll interval up to perfIdleCapMs.
func idleBackoff(idleMs, pollMs int) int {
	if cap := perfIdleCapMs(); idleMs < cap {
		return idleMs + pollMs
	}
	return idleMs
}

func PerfSummary() string {
	return fmt.Sprintf(
		"sock_buf=%dMB tun_queues=%d batch_size=%d tx_queue_len=%d poll_ms=%d tcp_streams=%d",
		perf.sockBuf>>20, perf.tunQueues, perf.batchSize, perf.txQLen, perf.pollMs, perf.tcpStreams,
	)
}

func validatePerf(t *config.TuningCfg) error {
	if t.SockBufMB != 0 && (t.SockBufMB < 1 || t.SockBufMB > 128) {
		return fmt.Errorf("[tuning] sock_buf_mb must be 1–128 (MB), got %d", t.SockBufMB)
	}
	if t.TunQueues != 0 && (t.TunQueues < 1 || t.TunQueues > MaxPerfQueues) {
		return fmt.Errorf("[tuning] tun_queues must be 1–%d, got %d", MaxPerfQueues, t.TunQueues)
	}
	if t.BatchSize != 0 && (t.BatchSize < 1 || t.BatchSize > maxPerfBatch) {
		return fmt.Errorf("[tuning] batch_size must be 1–%d, got %d", maxPerfBatch, t.BatchSize)
	}
	if t.TxQLen != 0 && (t.TxQLen < 100 || t.TxQLen > 100000) {
		return fmt.Errorf("[tuning] tx_queue_len must be 100–100000, got %d", t.TxQLen)
	}
	if t.PollMs != 0 && (t.PollMs < 1 || t.PollMs > 1000) {
		return fmt.Errorf("[tuning] poll_ms must be 1–1000, got %d", t.PollMs)
	}
	if t.TcpStreams != 0 && (t.TcpStreams < 1 || t.TcpStreams > MaxPerfQueues) {
		return fmt.Errorf("[tuning] tcp_streams must be 1–%d, got %d", MaxPerfQueues, t.TcpStreams)
	}
	return nil
}
