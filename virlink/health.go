// health.go — UDP handshake probe + HTTP health endpoint.
//
// After tunnel.Up() two goroutines start:
//   probeServer  — binds overlayIP:port/UDP, marks lastRx on each probe
//   probeSender  — dials peerIP:port/UDP every interval, sends probe
//   httpServer   — serves GET /health + GET /status on 0.0.0.0:port/TCP
//
// Handshake state transitions (based on age of last received probe):
//   waiting   → never received a probe
//   connected → age < 2 × interval   (healthy)
//   degraded  → age < 6 × interval   (some packet loss)
//   dead      → age ≥ 6 × interval   (HTTP 503)
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

const defaultHealthPort = 6543

// probe wire format: 4-byte magic + 8-byte unix-nano timestamp
var probeMagic = [4]byte{'V', 'L', 0x01, 0x70}

// ── HealthMgr ─────────────────────────────────────────────────────────────────

type HealthMgr struct {
	lastRxNano atomic.Int64  // unix nano of last received probe (0 = never)
	rxCount    atomic.Uint64
	txCount    atomic.Uint64
	startedAt  time.Time
	interval   time.Duration
}

func NewHealthMgr(since time.Time, interval time.Duration) *HealthMgr {
	return &HealthMgr{startedAt: since, interval: interval}
}

func (h *HealthMgr) markRx() {
	h.lastRxNano.Store(time.Now().UnixNano())
	h.rxCount.Add(1)
}

// LastSeenAge returns how long ago the last probe was received.
// Returns -1 if no probe has ever been received.
func (h *HealthMgr) LastSeenAge() time.Duration {
	t := h.lastRxNano.Load()
	if t == 0 {
		return -1
	}
	return time.Since(time.Unix(0, t))
}

// Handshake returns a human-readable connection state.
func (h *HealthMgr) Handshake() string {
	age := h.LastSeenAge()
	dead := h.interval * 6
	switch {
	case age < 0:
		return "waiting"
	case age < h.interval*2:
		return "connected"
	case age < dead:
		return "degraded"
	default:
		return "dead"
	}
}

// HandshakeColor returns an ANSI color for the current state (terminal only).
func (h *HealthMgr) HandshakeColor() string {
	switch h.Handshake() {
	case "connected":
		return cGreen
	case "degraded":
		return cYellow
	case "dead":
		return cRed
	default:
		return cGray
	}
}

// LastSeenStr returns a human-readable "N ago" or "never".
func (h *HealthMgr) LastSeenStr() string {
	age := h.LastSeenAge()
	if age < 0 {
		return "never"
	}
	return age.Round(time.Second).String() + " ago"
}

// ── probe server (listens for incoming probes from peer) ──────────────────────

func (h *HealthMgr) runProbeServer(overlayIP string, port int) {
	addr := fmt.Sprintf("%s:%d", overlayIP, port)
	var conn net.PacketConn
	var err error
	// overlay interface may take a moment to come up after tunnel.Up()
	for i := 0; i < 15; i++ {
		conn, err = net.ListenPacket("udp4", addr)
		if err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		logWarn(fmt.Sprintf("health probe server: bind %s failed: %v", addr, err))
		return
	}
	defer conn.Close()
	logInfo(fmt.Sprintf("health probe server  listen=%s", addr))

	buf := make([]byte, 32)
	for {
		n, _, rerr := conn.ReadFrom(buf)
		if rerr != nil {
			return
		}
		if n >= 4 && buf[0] == probeMagic[0] && buf[1] == probeMagic[1] &&
			buf[2] == probeMagic[2] && buf[3] == probeMagic[3] {
			h.markRx()
		}
	}
}

// ── probe sender (sends probes to peer overlay IP) ────────────────────────────

func (h *HealthMgr) runProbeSender(peerOverlay string, port int) {
	addr := fmt.Sprintf("%s:%d", peerOverlay, port)
	// build probe packet: 4-byte magic + 8-byte timestamp
	pkt := make([]byte, 12)
	copy(pkt[:4], probeMagic[:])

	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()
	for range ticker.C {
		binary.BigEndian.PutUint64(pkt[4:], uint64(time.Now().UnixNano()))
		conn, err := net.DialTimeout("udp4", addr, 2*time.Second)
		if err != nil {
			continue
		}
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Write(pkt)
		conn.Close()
		h.txCount.Add(1)
	}
}

// ── HTTP health + bench endpoints ─────────────────────────────────────────────

type healthJSON struct {
	Status       string       `json:"status"`
	Handshake    string       `json:"handshake"`
	LastSeen     string       `json:"last_seen"`
	Uptime       string       `json:"uptime"`
	Interface    string       `json:"interface"`
	OverlayIP    string       `json:"overlay_ip"`
	PeerIP       string       `json:"peer_ip"`
	TxProbes     uint64       `json:"tx_probes"`
	RxProbes     uint64       `json:"rx_probes"`
	LastBench    *BenchResult `json:"last_bench,omitempty"`
	BenchHint    string       `json:"bench_hint,omitempty"`
}

func (h *HealthMgr) runHTTPServer(port int, tun Tunnel, bm *BenchMgr) {
	mux := http.NewServeMux()

	// GET /health  — probe state + last bench result if available
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		hs := h.Handshake()
		code := http.StatusOK
		httpStatus := "ok"
		if hs == "dead" {
			code = http.StatusServiceUnavailable
			httpStatus = "degraded"
		}
		resp := healthJSON{
			Status:    httpStatus,
			Handshake: hs,
			LastSeen:  h.LastSeenStr(),
			Uptime:    time.Since(h.startedAt).Round(time.Second).String(),
			Interface: tun.DevName(),
			OverlayIP: tun.OverlayIP(),
			PeerIP:    tun.PeerIP(),
			TxProbes:  h.txCount.Load(),
			RxProbes:  h.rxCount.Load(),
		}
		if bm != nil {
			bm.mu.Lock()
			resp.LastBench = bm.lastResult
			bm.mu.Unlock()
			if resp.LastBench == nil {
				resp.BenchHint = fmt.Sprintf("GET :%d/bench to run bandwidth test", port)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/health", http.StatusFound)
	})

	mux.HandleFunc("/profile", handleProfileHTTP)

	// GET /bench  — run upload+download test through the tunnel overlay
	// Blocks until complete (up to ~60s), then returns and caches for 2min.
	mux.HandleFunc("/bench", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if bm == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintln(w, `{"error":"bench disabled"}`)
			return
		}
		// For non-GET requests return method not allowed
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// Use a longer write timeout for bench (may take up to 60s)
		if rw, ok := w.(http.ResponseWriter); ok {
			_ = rw
		}
		res := bm.RunBench()
		code := http.StatusOK
		if res != nil && res.Error != "" {
			code = http.StatusInternalServerError
		}
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(res)
	})

	// GET /  — HTML dashboard (auto-refreshes every 5s)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(dashboardHTML))
	})

	addr := fmt.Sprintf(":%d", port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 120 * time.Second, // bench can take up to 60s
	}
	logInfo(fmt.Sprintf("health HTTP  listen=0.0.0.0:%d  /health  /profile  /bench(port %d)", port, port+1))
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logWarn(fmt.Sprintf("health HTTP: %v", err))
	}
}

// ── Start — launches all goroutines ───────────────────────────────────────────

// Start begins the probe server, probe sender, bench server, and HTTP server.
// overlayIP must be the plain IP (no /prefix).
// peerIP must be the plain peer overlay IP.
func (h *HealthMgr) Start(overlayIP, peerIP string, port int, tun Tunnel) {
	bm := NewBenchMgr(port, peerIP)
	go h.runProbeServer(overlayIP, port)
	go h.runProbeSender(peerIP, port)
	go bm.runServer()
	go h.runHTTPServer(port, tun, bm)
}
