// stats.go — lock-free activity counters for CPU hotspot diagnosis.
//
// Each hot-path event calls statInc(id).  When [logging] profile=true a
// periodic report ranks counters by events/sec and prints hints.
package virlink

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"sync/atomic"
	"time"
)

const statMax = 40

const (
	statICMPTxPoll = iota
	statICMPTxRead
	statICMPTxSend
	statICMPTxDedup
	statICMPTxNoDst
	statICMPRxPoll
	statICMPRxRecv
	statICMPRxDropPeer
	statICMPRxDropProto
	statICMPRxDropSeq
	statICMPRxWrite

	statBIPTxPoll
	statBIPTxRead
	statBIPTxSend
	statBIPTxNoDst
	statBIPRxPoll
	statBIPRxRecv
	statBIPRxDrop
	statBIPRxWrite

	statUDPTxPoll
	statUDPTxRead
	statUDPTxSend
	statUDPTxNoDst
	statUDPRxRecv
	statUDPRxDrop
	statUDPRxWrite

	statTCPTxRead
	statTCPTxSend
	statTCPTxNoConn
	statTCPRxFrame
	statTCPRxWrite

	// TUN write failure counters (EAGAIN retries exhausted or other error).
	statICMPRxDropWrite
	statUDPRxDropWrite
	statBIPRxDropWrite
)

var statNames = [statMax]string{
	statICMPTxPoll:      "icmp.tx_poll",
	statICMPTxRead:      "icmp.tx_read",
	statICMPTxSend:      "icmp.tx_send",
	statICMPTxDedup:     "icmp.tx_dedup",
	statICMPTxNoDst:     "icmp.tx_nodst",
	statICMPRxPoll:      "icmp.rx_poll",
	statICMPRxRecv:      "icmp.rx_recv",
	statICMPRxDropPeer:  "icmp.rx_drop_peer",
	statICMPRxDropProto: "icmp.rx_drop_proto",
	statICMPRxDropSeq:   "icmp.rx_drop_seq",
	statICMPRxWrite:     "icmp.rx_write",

	statBIPTxPoll:  "bip.tx_poll",
	statBIPTxRead:  "bip.tx_read",
	statBIPTxSend:  "bip.tx_send",
	statBIPTxNoDst: "bip.tx_nodst",
	statBIPRxPoll:  "bip.rx_poll",
	statBIPRxRecv:  "bip.rx_recv",
	statBIPRxDrop:  "bip.rx_drop",
	statBIPRxWrite: "bip.rx_write",

	statUDPTxPoll:  "udp.tx_poll",
	statUDPTxRead:  "udp.tx_read",
	statUDPTxSend:  "udp.tx_send",
	statUDPTxNoDst: "udp.tx_nodst",
	statUDPRxRecv:  "udp.rx_recv",
	statUDPRxDrop:  "udp.rx_drop",
	statUDPRxWrite: "udp.rx_write",

	statTCPTxRead:   "tcp.tx_read",
	statTCPTxSend:   "tcp.tx_send",
	statTCPTxNoConn: "tcp.tx_noconn",
	statTCPRxFrame:  "tcp.rx_frame",
	statTCPRxWrite:  "tcp.rx_write",

	statICMPRxDropWrite: "icmp.rx_drop_write",
	statUDPRxDropWrite:  "udp.rx_drop_write",
	statBIPRxDropWrite:  "bip.rx_drop_write",
}

var (
	statCounts   [statMax]atomic.Uint64
	profEnabled  atomic.Bool
	profInterval time.Duration
	profSnap     struct {
		vals [statMax]uint64
		at   time.Time
	}
)

func initProfiler(cfg *Config) {
	profEnabled.Store(cfg.Logging.Profile)
	sec := cfg.Logging.ProfileInterval
	if sec <= 0 {
		sec = 30
	}
	profInterval = time.Duration(sec) * time.Second
	now := time.Now()
	profSnap.at = now
	for i := range statCounts {
		profSnap.vals[i] = statCounts[i].Load()
	}
}

func statInc(id int) {
	if id < 0 || id >= statMax {
		return
	}
	statCounts[id].Add(1)
}

func statAdd(id int, n uint64) {
	if id < 0 || id >= statMax || n == 0 {
		return
	}
	statCounts[id].Add(n)
}

type statRate struct {
	id    int
	name  string
	rate  float64
	total uint64
}

// profileReport logs ranked activity since the last snapshot.
func profileReport() {
	if !profEnabled.Load() {
		return
	}
	now := time.Now()
	elapsed := now.Sub(profSnap.at).Seconds()
	if elapsed < 1 {
		return
	}

	var rows []statRate
	var sumRate float64
	for i := 0; i < statMax; i++ {
		cur := statCounts[i].Load()
		delta := cur - profSnap.vals[i]
		if delta == 0 {
			continue
		}
		r := float64(delta) / elapsed
		rows = append(rows, statRate{id: i, name: statNames[i], rate: r, total: delta})
		sumRate += r
		profSnap.vals[i] = cur
	}
	profSnap.at = now

	if len(rows) == 0 {
		logProfile(fmt.Sprintf("idle  window=%ds  goroutines=%d", int(elapsed), runtime.NumGoroutine()))
		return
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].rate > rows[j].rate })

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	logProfile(fmt.Sprintf("activity  window=%ds  goroutines=%d  heap=%s  go_mem=%s",
		int(elapsed), runtime.NumGoroutine(), fmtBytes(ms.HeapInuse), fmtBytes(ms.Sys)))

	limit := len(rows)
	if limit > 12 {
		limit = 12
	}
	for _, r := range rows[:limit] {
		pct := 0.0
		if sumRate > 0 {
			pct = r.rate / sumRate * 100
		}
		logProfile(fmt.Sprintf("  %-22s %8s/s  %5.1f%%  (+%s)",
			r.name, fmtRate(r.rate), pct, fmtNum(r.total)))
	}

	for _, hint := range profileHints(rows, elapsed) {
		logProfile("  → " + hint)
	}
}

func profileHints(rows []statRate, elapsed float64) []string {
	var hints []string
	rates := make(map[string]float64, len(rows))
	for _, r := range rows {
		rates[r.name] = r.rate
	}

	poll := rates["icmp.tx_poll"] + rates["bip.tx_poll"] + rates["udp.tx_poll"] +
		rates["icmp.rx_poll"] + rates["bip.rx_poll"]
	send := rates["icmp.tx_send"] + rates["bip.tx_send"] + rates["udp.tx_send"] + rates["tcp.tx_send"]

	if poll > 100 && poll > send*3 {
		hints = append(hints, "high poll rate vs traffic — raise poll_ms or reduce tun_queues (idle CPU)")
	}
	if rates["icmp.tx_dedup"] > 10 {
		hints = append(hints, "icmp.tx_dedup active — multi-queue duplicate reads; try tun_queues=1")
	}
	if rates["icmp.rx_drop_peer"]+rates["icmp.rx_drop_proto"] > 50 {
		hints = append(hints, "many icmp drops — check peer IP / second tunnel instance running")
	}
	if rates["udp.rx_drop"]+rates["icmp.rx_drop_peer"] > 10 {
		hints = append(hints, "RX filter drops — wrong remote_ip or [mangle] wire src/dst mismatch")
	}
	if rates["udp.rx_drop_write"]+rates["icmp.rx_drop_write"]+rates["bip.rx_drop_write"] > 0 {
		hints = append(hints, "TUN write failures — packets received on wire but not injected into overlay")
	}
	if rates["udp.tx_nodst"]+rates["icmp.tx_nodst"]+rates["bip.tx_nodst"] > 0 {
		hints = append(hints, "TX nodst — server has not learned client address yet; client must send first")
	}
	if rates["udp.tx_read"] > 0 && rates["udp.tx_send"] == 0 {
		hints = append(hints, "UDP read from TUN but wire send=0 — check [diag] wire TX failed")
	}
	if rates["udp.rx_recv"] > 0 && rates["udp.rx_write"] == 0 {
		hints = append(hints, "UDP wire recv but tun write=0 — injection path broken")
	}
	if rates["tcp.tx_noconn"] > send && send > 0 {
		hints = append(hints, "tcp.tx_noconn high — TCP streams not connected yet")
	}
	if runtime.NumGoroutine() > perfTunQueues()+perfTcpStreams()+12 {
		hints = append(hints, fmt.Sprintf("goroutines=%d — more than expected; check duplicate processes", runtime.NumGoroutine()))
	}
	_ = elapsed
	return hints
}

func fmtRate(r float64) string {
	switch {
	case r >= 1_000_000:
		return fmt.Sprintf("%.1fM", r/1_000_000)
	case r >= 1000:
		return fmt.Sprintf("%.1fK", r/1000)
	default:
		return fmt.Sprintf("%.0f", r)
	}
}

// profileJSON is returned by GET /profile.
type profileJSON struct {
	WindowSec  int              `json:"window_sec"`
	Goroutines int              `json:"goroutines"`
	HeapBytes  uint64           `json:"heap_bytes"`
	SysBytes   uint64           `json:"sys_bytes"`
	Counters   []profileCounter `json:"counters"`
	Hints      []string         `json:"hints,omitempty"`
}

type profileCounter struct {
	Name  string  `json:"name"`
	Rate  float64 `json:"rate_per_sec"`
	Total uint64  `json:"total"`
	Pct   float64 `json:"pct"`
}

func profileSnapshotJSON() profileJSON {
	now := time.Now()
	elapsed := now.Sub(profSnap.at).Seconds()
	if elapsed < 1 {
		elapsed = 1
	}

	var rows []statRate
	var sumRate float64
	for i := 0; i < statMax; i++ {
		cur := statCounts[i].Load()
		delta := cur - profSnap.vals[i]
		if delta == 0 {
			continue
		}
		r := float64(delta) / elapsed
		rows = append(rows, statRate{id: i, name: statNames[i], rate: r, total: delta})
		sumRate += r
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].rate > rows[j].rate })

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	out := profileJSON{
		WindowSec:  int(elapsed),
		Goroutines: runtime.NumGoroutine(),
		HeapBytes:  ms.HeapInuse,
		SysBytes:   ms.Sys,
	}
	for _, r := range rows {
		pct := 0.0
		if sumRate > 0 {
			pct = r.rate / sumRate * 100
		}
		out.Counters = append(out.Counters, profileCounter{
			Name: r.name, Rate: r.rate, Total: r.total, Pct: pct,
		})
	}
	out.Hints = profileHints(rows, elapsed)
	return out
}

func handleProfileHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !profEnabled.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "profile disabled — set [logging] profile = true in config.toml",
		})
		return
	}
	_ = json.NewEncoder(w).Encode(profileSnapshotJSON())
}

func startProfileLoop(stop <-chan struct{}) {
	if !profEnabled.Load() {
		return
	}
	logProfile(fmt.Sprintf("profiler on  interval=%s  endpoint=GET /profile", profInterval))
	ticker := time.NewTicker(profInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			profileReport()
		case <-stop:
			return
		}
	}
}
