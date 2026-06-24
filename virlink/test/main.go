// virlink-test — bidirectional protocol benchmark & validation suite.
//
// Usage:
//
//	# Two real machines (SSH)
//	sudo ./virlink-test \
//	  --host-a 81.12.35.242 \
//	  --host-b 5.75.206.15 --ssh-user root --ssh-key ~/.ssh/id_ed25519 \
//	  --overlay 10.99.0.0/30 \
//	  --backend ssh
//
//	# API-only (virlink already running)
//	./virlink-test \
//	  --backend api \
//	  --overlay-a 10.20.10.1 \
//	  --overlay-b 10.20.10.2 \
//	  --health-port 6543
//
//	# Local processes (single host, two processes, needs root + two IPs)
//	sudo ./virlink-test \
//	  --host-a 127.0.0.1 --host-b 127.0.0.2 \
//	  --overlay 10.99.0.0/30 \
//	  --backend local \
//	  --virlink-bin /opt/virlink/virlink
//
// Flags:
//
//	--only      comma-separated list of protocol names to run (default: all)
//	--duration  test duration per direction (default: 10s)
//	--pings     ping count for latency measurement (default: 30)
//	--bidirect  run both A→B and B→A (default: true)
//	--json      write JSON report to this file
//	--verbose   print per-stream debug output
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const testVersion = "1.0.0"

// ── config types ──────────────────────────────────────────────────────────────

type HostConfig struct {
	IP         string
	SSHUser    string
	SSHKey     string
	SSHPort    int
	VirLinkBin string // remote binary path
}

type TestConfig struct {
	HostA      HostConfig
	HostB      HostConfig
	OverlayCIDR string
	Backend    string // local | ssh | api

	// api-only mode: overlay IPs already known
	OverlayA string
	OverlayB string

	HealthPort int
	VirLinkBin string  // local binary

	// test parameters
	Only       []string      // protocol filter (empty = all)
	Bidirect   bool
	WarmupWait time.Duration // time to wait for tunnel to come up
	PingCount  int
	Verbose    bool

	// output
	JSONOut string
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	cfg := parseFlags()
	PrintBanner(cfg)

	// select protocols
	protos := selectProtos(cfg.Only, AllProtos)
	if len(protos) == 0 {
		fmt.Fprintln(os.Stderr, "no protocols selected")
		os.Exit(1)
	}
	fmt.Printf("  %s  %s\n\n",
		c(colGray, "protocols"),
		c(colCyan, protoNames(protos)))

	// prepare tmp dir for configs + logs
	tmpDir, err := os.MkdirTemp("", "virlink-test-*")
	if err != nil {
		die("tmp dir: " + err.Error())
	}
	defer os.RemoveAll(tmpDir)
	if cfg.Verbose {
		fmt.Printf("  %s  %s\n", c(colGray, "tmp"), tmpDir)
	}

	// run the matrix
	var results []ProtoResult
	PrintTableHeader()

	directions := []Direction{DirAB}
	if cfg.Bidirect {
		directions = append(directions, DirBA)
	}

	for _, proto := range protos {
		for _, dir := range directions {
			r := runOne(cfg, proto, dir, tmpDir)
			r.Recommendation = buildRecommendation(&r, cfg)
			results = append(results, r)
			PrintRow(r)
		}
	}

	sum := computeSummary(results)
	PrintTableFooter(sum)
	PrintRecommendations(results)

	// write JSON
	if cfg.JSONOut != "" {
		report := &Report{
			Version:  testVersion,
			TestedAt: time.Now(),
			HostA:    cfg.HostA.IP,
			HostB:    cfg.HostB.IP,
			Overlay:  cfg.OverlayCIDR,
			Results:  results,
			Summary:  sum,
		}
		if err := WriteJSONReport(cfg.JSONOut, report); err != nil {
			fmt.Fprintf(os.Stderr, "json report: %v\n", err)
		} else {
			fmt.Printf("  %s  %s\n\n", c(colGray, "report →"), cfg.JSONOut)
		}
	}

	if sum.Fail > 0 {
		os.Exit(1)
	}
}

// ── runOne ────────────────────────────────────────────────────────────────────

func runOne(cfg *TestConfig, proto Proto, dir Direction, tmpDir string) ProtoResult {
	r := ProtoResult{
		Protocol:  proto.Name,
		Label:     proto.Label,
		Direction: dir,
		TestedAt:  time.Now(),
	}
	start := time.Now()

	logf := func(format string, a ...any) {
		if cfg.Verbose {
			fmt.Printf("    "+format+"\n", a...)
		}
	}

	defer func() { r.Duration = time.Since(start) }()

	// ── 1. start tunnel pair ─────────────────────────────────────────────────
	var hA, hB *TunnelHandle

	switch cfg.Backend {
	case "api":
		// tunnels already running; just point at their overlay IPs
		hA = APIHandle(cfg.OverlayA, cfg.OverlayB, cfg.HealthPort)
		hB = APIHandle(cfg.OverlayB, cfg.OverlayA, cfg.HealthPort)

	case "ssh":
		var err error
		hA, hB, err = SSHPair(cfg, proto, dir, tmpDir)
		if err != nil {
			r.Status = "error"
			r.ErrorMsg = "startup: " + err.Error()
			return r
		}
		defer hA.Kill()
		defer hB.Kill()

	default: // "local"
		var err error
		hA, hB, err = LocalPair(cfg, proto, dir, tmpDir)
		if err != nil {
			r.Status = "error"
			r.ErrorMsg = "startup: " + err.Error()
			return r
		}
		defer hA.Kill()
		defer hB.Kill()
	}

	// ── 2. wait for tunnel to be ready ───────────────────────────────────────
	logf("waiting for tunnel (up to %s)...", cfg.WarmupWait)
	// We poll the client side (hB in A→B direction, hA in B→A)
	clientHandle := hB
	if dir == DirBA {
		clientHandle = hA
	}
	if err := waitReady(clientHandle, cfg.WarmupWait, 2*time.Second); err != nil {
		r.Status = "fail"
		r.ErrorMsg = "not connected: " + err.Error()
		return r
	}
	logf("tunnel ready")

	// ── 3. throughput benchmark ──────────────────────────────────────────────
	logf("running bench (download then upload)...")
	bench, err := runBench(clientHandle, 5*time.Second)
	if err != nil {
		r.Status = "fail"
		r.ErrorMsg = "bench: " + err.Error()
		return r
	}
	r.DownloadMbps = bench.DownloadMbps
	r.UploadMbps = bench.UploadMbps
	logf("bench: ↓%.1f Mbps  ↑%.1f Mbps", bench.DownloadMbps, bench.UploadMbps)

	// ── 4. latency + packet loss ─────────────────────────────────────────────
	logf("measuring latency (%d pings)...", cfg.PingCount)
	lat, err := measureLatency(clientHandle.PeerOverIP, cfg.PingCount, 200*time.Millisecond)
	if err != nil {
		// latency failure is non-fatal; record zero values
		logf("latency: %v", err)
		r.LossPct = -1
	} else {
		r.LatencyP50Ms = lat.P50Ms
		r.LatencyP95Ms = lat.P95Ms
		r.LatencyP99Ms = lat.P99Ms
		r.LossPct = lat.LossPct
		logf("latency p50=%.2f p95=%.2f p99=%.2f loss=%.1f%%",
			lat.P50Ms, lat.P95Ms, lat.P99Ms, lat.LossPct)
	}

	// ── 5. resource usage ────────────────────────────────────────────────────
	if cfg.Backend != "api" && hA.proc != nil {
		logf("sampling proc stats...")
		if ps, err := sampleProc(hA.proc.Process.Pid); err == nil {
			r.ServerCPUPct = ps.CPUPct
			r.ServerMemMiB = ps.MemRSSMiB
		}
		if ps, err := sampleProc(hB.proc.Process.Pid); err == nil {
			r.ClientCPUPct = ps.CPUPct
			r.ClientMemMiB = ps.MemRSSMiB
		}
	}

	// ── 6. success ───────────────────────────────────────────────────────────
	r.Status = "pass"
	return r
}

// ── CLI parsing ───────────────────────────────────────────────────────────────

func parseFlags() *TestConfig {
	hostA := flag.String("host-a", "", "IP of host A (this machine)")
	hostB := flag.String("host-b", "", "IP of host B (peer)")
	sshUser := flag.String("ssh-user", "root", "SSH username for host B")
	sshKey := flag.String("ssh-key", "", "SSH private key for host B")
	sshPort := flag.Int("ssh-port", 22, "SSH port for host B")
	remoteBin := flag.String("remote-bin", "/opt/virlink/virlink", "virlink binary path on host B")

	backend := flag.String("backend", "local", "execution backend: local | ssh | api")
	overlay := flag.String("overlay", "10.99.0.0/30", "overlay CIDR (A=.1, B=.2)")
	overlayA := flag.String("overlay-a", "", "host A overlay IP (api backend)")
	overlayB := flag.String("overlay-b", "", "host B overlay IP (api backend)")
	healthPort := flag.Int("health-port", 6543, "virlink health port")
	virLink := flag.String("virlink-bin", "/opt/virlink/virlink", "local virlink binary")

	only := flag.String("only", "", "comma-separated protocol names to test (default: all)")
	bidirect := flag.Bool("bidirect", true, "test both A→B and B→A directions")
	warmup := flag.Duration("warmup", 30*time.Second, "max wait for tunnel to connect")
	pings := flag.Int("pings", 30, "ping count for latency measurement")
	verbose := flag.Bool("verbose", false, "verbose per-step logging")
	jsonOut := flag.String("json", "", "write JSON report to file")

	flag.Parse()

	cfg := &TestConfig{
		HostA: HostConfig{IP: *hostA},
		HostB: HostConfig{
			IP: *hostB, SSHUser: *sshUser, SSHKey: *sshKey,
			SSHPort: *sshPort, VirLinkBin: *remoteBin,
		},
		OverlayCIDR: *overlay,
		Backend:     *backend,
		OverlayA:    *overlayA,
		OverlayB:    *overlayB,
		HealthPort:  *healthPort,
		VirLinkBin:  *virLink,
		Bidirect:    *bidirect,
		WarmupWait:  *warmup,
		PingCount:   *pings,
		Verbose:     *verbose,
		JSONOut:     *jsonOut,
	}

	// default host A to this machine's outbound IP if not set
	if cfg.HostA.IP == "" {
		cfg.HostA.IP = detectLocalIP()
	}
	if cfg.Backend == "ssh" && cfg.HostB.IP == "" {
		die("--host-b required for ssh backend")
	}
	if cfg.Backend == "api" {
		if cfg.OverlayA == "" || cfg.OverlayB == "" {
			die("--overlay-a and --overlay-b required for api backend")
		}
	}

	if *only != "" {
		cfg.Only = strings.Split(*only, ",")
		for i, s := range cfg.Only {
			cfg.Only[i] = strings.TrimSpace(s)
		}
	}

	return cfg
}

// ── helpers ───────────────────────────────────────────────────────────────────

func selectProtos(only []string, all []Proto) []Proto {
	if len(only) == 0 {
		return all
	}
	set := make(map[string]bool, len(only))
	for _, n := range only {
		set[n] = true
	}
	var out []Proto
	for _, p := range all {
		if set[p.Name] {
			out = append(out, p)
		}
	}
	return out
}

func protoNames(ps []Proto) string {
	names := make([]string, len(ps))
	for i, p := range ps {
		names[i] = p.Name
	}
	return strings.Join(names, "  ")
}

func detectLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	addr := conn.LocalAddr().(*net.UDPAddr)
	return addr.IP.String()
}

func die(msg string) {
	fmt.Fprintln(os.Stderr, c(colRed, "✗")+" "+msg)
	os.Exit(1)
}

