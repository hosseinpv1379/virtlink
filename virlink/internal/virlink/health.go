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
package virlink

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"syscall"
	"time"
)

const defaultHealthPort = 6543

const healthPortSpan = 400 // ports 6543–6942 via healthPortOffset

// healthPortOffset returns a stable offset in [0, healthPortSpan) from tunnel name.
func healthPortOffset(name string) int {
	h := uint32(2166136261)
	for i := 0; i < len(name); i++ {
		h ^= uint32(name[i])
		h *= 16777619
	}
	return int(h % healthPortSpan)
}

// applyHealthPort assigns a unique health port when unset or left at default.
// Port is derived from tunnel type + overlay CIDR so client and server always
// agree (tunnel.name / dev name may differ per host).
func applyHealthPort(c *Config) {
	if c.Health.Port != 0 && c.Health.Port != defaultHealthPort {
		return
	}
	key := c.Tunnel.Type + "|" + c.Tunnel.CIDR
	c.Health.Port = defaultHealthPort + healthPortOffset(key)
}

func listenTCPReuseAddr(addr string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var setErr error
			err := c.Control(func(fd uintptr) {
				setErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			})
			if err != nil {
				return err
			}
			return setErr
		},
	}
	return lc.Listen(context.Background(), "tcp4", addr)
}

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

// NoteTunnelAlive marks the tunnel as alive based on wire traffic (not overlay UDP probes).
// Overlay probes traverse stack→TUN→wire→TUN→stack and can fail independently of the
// tunnel; marking alive on valid wire RX keeps hs=connected when data actually flows.
func NoteTunnelAlive() {
	if h := activeTunnelHealth.Load(); h != nil {
		h.markRx()
	}
}

var activeTunnelHealth atomic.Pointer[HealthMgr]

// BindTunnelHealth registers the process health manager for wire-level keepalive.
func BindTunnelHealth(h *HealthMgr) { activeTunnelHealth.Store(h) }

// UnbindTunnelHealth clears the wire-level health binding on shutdown.
func UnbindTunnelHealth() { activeTunnelHealth.Store(nil) }

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

func (h *HealthMgr) runProbeSender(localOverlay, peerOverlay string, port int) {
	localIP := net.ParseIP(localOverlay)
	if localIP = localIP.To4(); localIP == nil {
		return
	}
	peerIP := net.ParseIP(peerOverlay)
	if peerIP = peerIP.To4(); peerIP == nil {
		return
	}
	peerAddr := &net.UDPAddr{IP: peerIP, Port: port}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: localIP, Port: 0})
	if err != nil {
		logWarn(fmt.Sprintf("health probe sender: bind %s: %v", localIP, err))
		return
	}
	defer conn.Close()
	tuneUDPConn(conn)
	logInfo(fmt.Sprintf("health probe sender  peer=%s:%d  interval=%s", peerOverlay, port, h.interval))

	pkt := make([]byte, 12)
	copy(pkt[:4], probeMagic[:])

	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()
	for range ticker.C {
		binary.BigEndian.PutUint64(pkt[4:], uint64(time.Now().UnixNano()))
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.WriteToUDP(pkt, peerAddr); err != nil {
			logDebug("health probe tx: " + err.Error())
			continue
		}
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
	Selected     string       `json:"selected_interface,omitempty"`
	OverlayIP    string       `json:"overlay_ip"`
	PeerIP       string       `json:"peer_ip"`
	ProbePort    int          `json:"probe_port"`
	HTTPPort     int          `json:"http_port"`
	BenchPort    int          `json:"bench_port"`
	PanelURL     string       `json:"panel_url,omitempty"`
	TxProbes     uint64       `json:"tx_probes"`
	RxProbes     uint64       `json:"rx_probes"`
	Interfaces   []ifaceJSON  `json:"interfaces,omitempty"`
	LastBench    *BenchResult `json:"last_bench,omitempty"`
	BenchHint    string       `json:"bench_hint,omitempty"`
}

func (h *HealthMgr) buildHealthJSON(tun Tunnel, bm *BenchMgr, probePort, httpPort int, selected string) healthJSON {
	hs := h.Handshake()
	httpStatus := "ok"
	if hs == "dead" {
		httpStatus = "degraded"
	}
	overlayPlain := plainIP(tun.OverlayIP())
	iface := tun.DevName()
	if selected != "" && selected != "all" {
		iface = selected
	}
	devs := tunnelMonitorDevs(tun)
	ifaces := collectIfaceStats(devs, overlayPlain)

	resp := healthJSON{
		Status:     httpStatus,
		Handshake:  hs,
		LastSeen:   h.LastSeenStr(),
		Uptime:     time.Since(h.startedAt).Round(time.Second).String(),
		Interface:  iface,
		Selected:   selected,
		OverlayIP:  overlayPlain,
		PeerIP:     tun.PeerIP(),
		ProbePort:  probePort,
		HTTPPort:   httpPort,
		BenchPort:  httpPort + 1,
		PanelURL:   fmtPanelURL(overlayPlain, httpPort),
		TxProbes:   h.txCount.Load(),
		RxProbes:   h.rxCount.Load(),
		Interfaces: ifaces,
	}
	if sel := pickIfaceStats(ifaces, selected); sel != nil && selected != "" && selected != "all" {
		resp.Interface = sel.Name
	}
	if bm != nil {
		bm.mu.Lock()
		resp.LastBench = bm.lastResult
		bm.mu.Unlock()
		if resp.LastBench == nil {
			resp.BenchHint = fmt.Sprintf("GET /bench  or  /bench?iface=worker-name  (TCP data :%d)", httpPort+1)
		}
	}
	return resp
}

func (h *HealthMgr) runHTTPServer(overlayIP string, httpPort, probePort int, tun Tunnel, bm *BenchMgr) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/interfaces", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		devs := tunnelMonitorDevs(tun)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"overlay_ip": plainIP(tun.OverlayIP()),
			"peer_ip":    tun.PeerIP(),
			"http_port":  httpPort,
			"probe_port": probePort,
			"bench_port": httpPort + 1,
			"interfaces": collectIfaceStats(devs, plainIP(tun.OverlayIP())),
		})
	})

	// GET /health  — probe state + per-interface stats
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		selected := r.URL.Query().Get("iface")
		if selected == "" {
			selected = r.URL.Query().Get("interface")
		}
		if selected != "" && !validPanelIface(selected, tun) {
			http.Error(w, "unknown interface", http.StatusBadRequest)
			return
		}
		resp := h.buildHealthJSON(tun, bm, probePort, httpPort, selected)
		code := http.StatusOK
		if resp.Handshake == "dead" {
			code = http.StatusServiceUnavailable
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
	mux.HandleFunc("/bench", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if bm == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintln(w, `{"error":"bench disabled"}`)
			return
		}
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		via := r.URL.Query().Get("iface")
		if via == "" {
			via = r.URL.Query().Get("interface")
		}
		if via != "" && via != "all" && !validPanelIface(via, tun) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unknown interface: " + via})
			return
		}
		devs := tunnelMonitorDevs(tun)
		if via == "all" && len(devs) > 1 {
			out := bm.RunBenchAllWorkers(devs)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(out)
			return
		}
		res := bm.RunBenchVia(via)
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

	addr := fmt.Sprintf("%s:%d", overlayIP, httpPort)
	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 120 * time.Second,
	}
	ln, err := listenTCPReuseAddr(addr)
	if err != nil {
		logWarn(fmt.Sprintf("health HTTP: listen %s: %v", addr, err))
		return
	}
	logInfo(fmt.Sprintf("panel HTTP  listen=%s  /  /health  /bench  probe_udp=:%d  bench_tcp=:%d",
		addr, probePort, httpPort+1))
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		logWarn(fmt.Sprintf("health HTTP: %v", err))
	}
}

// ── Start — launches all goroutines ───────────────────────────────────────────

// Start begins the probe server, probe sender, bench server, and HTTP server.
// overlayIP must be the plain IP (no /prefix).
// peerIP must be the plain peer overlay IP.
func (h *HealthMgr) Start(overlayIP, peerIP string, probePort, httpPort int, tun Tunnel) {
	bm := NewBenchMgr(httpPort, peerIP, overlayIP, tun)
	go h.runProbeServer(overlayIP, probePort)
	go h.runProbeSender(overlayIP, peerIP, probePort)
	go bm.runServer()
	go h.runHTTPServer(overlayIP, httpPort, probePort, tun, bm)
}
