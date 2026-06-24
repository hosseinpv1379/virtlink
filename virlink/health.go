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

// ── HTTP health endpoint ───────────────────────────────────────────────────────

type healthJSON struct {
	Status    string `json:"status"`
	Handshake string `json:"handshake"`
	LastSeen  string `json:"last_seen"`
	Uptime    string `json:"uptime"`
	Interface string `json:"interface"`
	OverlayIP string `json:"overlay_ip"`
	PeerIP    string `json:"peer_ip"`
	TxProbes  uint64 `json:"tx_probes"`
	RxProbes  uint64 `json:"rx_probes"`
}

func (h *HealthMgr) runHTTPServer(port int, tun Tunnel) {
	mux := http.NewServeMux()

	handler := func(w http.ResponseWriter, r *http.Request) {
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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(resp)
	}

	mux.HandleFunc("/health", handler)
	mux.HandleFunc("/status", handler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/health", http.StatusFound)
	})

	addr := fmt.Sprintf(":%d", port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	logInfo(fmt.Sprintf("health HTTP server   listen=0.0.0.0:%d  GET /health", port))
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logWarn(fmt.Sprintf("health HTTP: %v", err))
	}
}

// ── Start — launches all three goroutines ─────────────────────────────────────

// Start begins the probe server, probe sender, and HTTP health server.
// overlayIP must be the plain IP (no /prefix).
// peerIP must be the plain peer overlay IP.
func (h *HealthMgr) Start(overlayIP, peerIP string, port int, tun Tunnel) {
	go h.runProbeServer(overlayIP, port)
	go h.runProbeSender(peerIP, port)
	go h.runHTTPServer(port, tun)
}
