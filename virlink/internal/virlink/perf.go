// perf.go — runtime performance knobs from [tuning] in config.toml.
package virlink

import (
	"fmt"
	"runtime"
)

const (
	maxPerfQueues = 16
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
	case "icmp", "udp", "tcp", "bip", "udp-obfs", "openvpn", "hysteria2", "wireguard", "amneziawg":
		return true
	}
	return false
}

// initUserspacePerfDefaults picks per-protocol defaults: low goroutine count,
// enough buffers/batching for throughput without the 16-queue overhead.
func initUserspacePerfDefaults(c *Config) {
	ncpu := runtime.NumCPU()
	if ncpu > 4 {
		ncpu = 4
	}
	if ncpu < 1 {
		ncpu = 1
	}

	perf = perfRuntime{
		sockBuf:    defSockBufMB << 20,
		tunQueues:  1,
		batchSize:  defBatchSize,
		txQLen:     defTxQLen,
		pollMs:     defPollMs,
		tcpStreams: 2,
	}

	switch c.Tunnel.Type {
	case "icmp":
		// 2 queues + sendmmsg batch = best throughput/resource ratio for ICMP
		perf.sockBuf = 64 << 20
		perf.tunQueues = clampInt(ncpu, 2, 4)
		perf.batchSize = 64
		perf.pollMs = 5
	case "udp":
		// single queue + single poller — UDP socket is already parallel enough
		perf.sockBuf = 32 << 20
		perf.tunQueues = 1
		perf.pollMs = 10
	case "bip":
		perf.sockBuf = 32 << 20
		perf.tunQueues = 1
		perf.pollMs = 10
	case "tcp":
		perf.sockBuf = 32 << 20
		perf.tunQueues = 1
		perf.tcpStreams = clampInt(ncpu, 2, 4)
		perf.pollMs = 10
	case "udp-obfs":
		perf.sockBuf = 16 << 20
		perf.tunQueues = 1
		perf.pollMs = 10
	case "openvpn":
		perf.tunQueues = 1
		switch tuningMode(c) {
		case tuningResource:
			perf.pollMs = 100
		case tuningLatency:
			perf.pollMs = 20
		default:
			perf.pollMs = 50
		}
	case "hysteria2":
		perf.tunQueues = 1
		perf.pollMs = 50
	case "wireguard":
		perf.tunQueues = 1
		perf.pollMs = 50
	case "amneziawg":
		perf.tunQueues = 1
		perf.pollMs = 50
	}
}

// applyPerfFromConfig loads [tuning] performance fields (0 = default for that field).
func applyPerfFromConfig(c *Config) {
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
		perf.tunQueues = clampInt(t.TunQueues, 1, maxPerfQueues)
	}
	if t.BatchSize > 0 {
		perf.batchSize = clampInt(t.BatchSize, 1, maxPerfBatch)
	}
	if t.PollMs > 0 {
		perf.pollMs = clampInt(t.PollMs, 1, 1000)
	}
	if t.TcpStreams > 0 {
		perf.tcpStreams = clampInt(t.TcpStreams, 1, maxPerfQueues)
	} else {
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

func perfSockBuf() int       { return perf.sockBuf }
func perfTunQueues() int     { return perf.tunQueues }
func perfBatchSize() int     { return perf.batchSize }
func perfTxQLen() int         { return perf.txQLen }
func perfPollMs() int         { return perf.pollMs }
func perfTcpStreams() int     { return perf.tcpStreams }

func perfSummary() string {
	return fmt.Sprintf(
		"sock_buf=%dMB tun_queues=%d batch_size=%d tx_queue_len=%d poll_ms=%d tcp_streams=%d",
		perf.sockBuf>>20, perf.tunQueues, perf.batchSize, perf.txQLen, perf.pollMs, perf.tcpStreams,
	)
}

func validatePerf(t *TuningCfg) error {
	if t.SockBufMB != 0 && (t.SockBufMB < 1 || t.SockBufMB > 128) {
		return fmt.Errorf("[tuning] sock_buf_mb must be 1–128 (MB), got %d", t.SockBufMB)
	}
	if t.TunQueues != 0 && (t.TunQueues < 1 || t.TunQueues > maxPerfQueues) {
		return fmt.Errorf("[tuning] tun_queues must be 1–%d, got %d", maxPerfQueues, t.TunQueues)
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
	if t.TcpStreams != 0 && (t.TcpStreams < 1 || t.TcpStreams > maxPerfQueues) {
		return fmt.Errorf("[tuning] tcp_streams must be 1–%d, got %d", maxPerfQueues, t.TcpStreams)
	}
	return nil
}
