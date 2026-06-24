// metrics.go — measurement helpers.
//
// Covers:
//   - waitReady   : poll GET /health until handshake = connected (or timeout)
//   - runBench    : trigger GET /bench and parse result
//   - measureLatency : exec ping -c N through the overlay, parse p50/p95/p99
//   - procStats   : read /proc/<pid>/stat + /proc/<pid>/status for CPU & mem
//   - measureIntegrity : send N KB through overlay TCP, verify SHA-256
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ── health / bench JSON types (mirror virlink/health.go + bench.go) ──────────

type HealthResponse struct {
	Status     string  `json:"status"`        // waiting | connected | degraded | dead
	ProbesRx   uint64  `json:"probes_rx"`
	ProbesTx   uint64  `json:"probes_tx"`
	LastSeenMs float64 `json:"last_seen_ms"`
	UptimeSec  float64 `json:"uptime_sec"`
}

type BenchResponse struct {
	DownloadMbps  float64 `json:"download_mbps"`
	DownloadMBs   float64 `json:"download_mb_s"`
	UploadMbps    float64 `json:"upload_mbps"`
	UploadMBs     float64 `json:"upload_mb_s"`
	Streams       int     `json:"streams"`
	TestDuration  string  `json:"test_duration"`
	TotalDuration string  `json:"total_duration"`
	TestedAt      string  `json:"tested_at"`
	Error         string  `json:"error,omitempty"`
}

// ── LatencyResult ─────────────────────────────────────────────────────────────

type LatencyResult struct {
	P50Ms   float64
	P95Ms   float64
	P99Ms   float64
	MinMs   float64
	MaxMs   float64
	LossPct float64
	Count   int
	// raw RTTs in ms (up to 100 samples)
	Samples []float64
}

// ── ProcStats ─────────────────────────────────────────────────────────────────

type ProcStats struct {
	CPUPct    float64 // %cpu over sample window
	MemRSSMiB float64 // resident set size in MiB
}

// ── waitReady ─────────────────────────────────────────────────────────────────

// waitReady polls GET http://<overlayIP>:<healthPort>/health until status is
// "connected", or until timeout.  Polls every pollInterval.
func waitReady(handle *TunnelHandle, timeout, pollInterval time.Duration) error {
	deadline := time.Now().Add(timeout)
	url := fmt.Sprintf("http://%s:%d/health", handle.OverlayIP, handle.HealthPort)
	client := &http.Client{Timeout: 3 * time.Second}

	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			var hr HealthResponse
			_ = json.NewDecoder(resp.Body).Decode(&hr)
			resp.Body.Close()
			if hr.Status == "connected" {
				return nil
			}
		}
		time.Sleep(pollInterval)
	}
	// last attempt
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("health endpoint unreachable after %s: %w", timeout, err)
	}
	defer resp.Body.Close()
	var hr HealthResponse
	_ = json.NewDecoder(resp.Body).Decode(&hr)
	if hr.Status != "connected" {
		return fmt.Errorf("tunnel not connected (status=%q) after %s", hr.Status, timeout)
	}
	return nil
}

// getHealth fetches the current health snapshot.
func getHealth(handle *TunnelHandle) (*HealthResponse, error) {
	url := fmt.Sprintf("http://%s:%d/health", handle.OverlayIP, handle.HealthPort)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var hr HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&hr); err != nil {
		return nil, err
	}
	return &hr, nil
}

// ── runBench ──────────────────────────────────────────────────────────────────

// runBench triggers GET /bench on the client side.  The virlink bench client
// connects through the overlay to the server.
// We hit the client's health API (it drives the test from its side).
func runBench(handle *TunnelHandle, extraTimeout time.Duration) (*BenchResponse, error) {
	totalTimeout := 2*5*time.Second + 15*time.Second + extraTimeout // 2 × 5s runs + overhead
	url := fmt.Sprintf("http://%s:%d/bench", handle.OverlayIP, handle.HealthPort)
	client := &http.Client{Timeout: totalTimeout}

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("bench request failed: %w", err)
	}
	defer resp.Body.Close()

	var br BenchResponse
	if err := json.NewDecoder(resp.Body).Decode(&br); err != nil {
		return nil, fmt.Errorf("bench response decode: %w", err)
	}
	if br.Error != "" {
		return &br, fmt.Errorf("bench error: %s", br.Error)
	}
	return &br, nil
}

// ── measureLatency ────────────────────────────────────────────────────────────

// measureLatency pings peerOverlayIP from the current host and parses RTTs.
// Uses OS "ping" command; works on Linux (and macOS for dev testing).
func measureLatency(peerOverlayIP string, count int, interval time.Duration) (*LatencyResult, error) {
	if count <= 0 {
		count = 30
	}

	var args []string
	if runtime.GOOS == "darwin" {
		args = []string{"-c", strconv.Itoa(count),
			"-i", fmt.Sprintf("%.2f", interval.Seconds()), peerOverlayIP}
	} else {
		args = []string{"-c", strconv.Itoa(count),
			"-i", fmt.Sprintf("%.3f", interval.Seconds()),
			"-W", "1", peerOverlayIP}
	}

	cmd := exec.Command("ping", args...)
	out, err := cmd.CombinedOutput()
	// ping exits non-zero on packet loss but still produces output
	_ = err

	return parsePingOutput(string(out), count)
}

// parsePingOutput parses the RTT lines and summary from ping output.
func parsePingOutput(output string, sentCount int) (*LatencyResult, error) {
	var rtts []float64
	var lossLine string

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		// RTT line: "64 bytes from 10.99.0.2: icmp_seq=1 ttl=64 time=0.821 ms"
		if strings.Contains(line, "time=") {
			idx := strings.Index(line, "time=")
			if idx >= 0 {
				rest := line[idx+5:]
				fields := strings.Fields(rest)
				if len(fields) >= 1 {
					v, err := strconv.ParseFloat(strings.TrimSuffix(fields[0], "ms"), 64)
					if err == nil {
						rtts = append(rtts, v)
					}
				}
			}
		}
		// loss line: "5 packets transmitted, 4 received, 20% packet loss"
		if strings.Contains(line, "packet loss") || strings.Contains(line, "packets transmitted") {
			lossLine = line
		}
	}

	if len(rtts) == 0 {
		return nil, fmt.Errorf("no RTT samples from ping output:\n%s", output)
	}

	// parse loss
	var lossPct float64
	if lossLine != "" {
		for _, field := range strings.Fields(lossLine) {
			if strings.HasSuffix(field, "%") {
				v, _ := strconv.ParseFloat(strings.TrimSuffix(field, "%"), 64)
				lossPct = v
				break
			}
		}
	} else if sentCount > 0 {
		lossPct = float64(sentCount-len(rtts)) / float64(sentCount) * 100
	}

	sort.Float64s(rtts)

	return &LatencyResult{
		P50Ms:   percentile(rtts, 50),
		P95Ms:   percentile(rtts, 95),
		P99Ms:   percentile(rtts, 99),
		MinMs:   rtts[0],
		MaxMs:   rtts[len(rtts)-1],
		LossPct: lossPct,
		Count:   len(rtts),
		Samples: rtts,
	}, nil
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := (p / 100) * float64(len(sorted)-1)
	lo := int(math.Floor(idx))
	hi := int(math.Ceil(idx))
	if lo == hi {
		return sorted[lo]
	}
	frac := idx - float64(lo)
	return sorted[lo]*(1-frac) + sorted[hi]*frac
}

// ── procStats ─────────────────────────────────────────────────────────────────

// sampleProc takes a CPU/mem snapshot of a running process.
// pid=0 → skip (remote process or unknown)
func sampleProc(pid int) (*ProcStats, error) {
	if pid <= 0 || runtime.GOOS != "linux" {
		return &ProcStats{}, nil
	}

	// read /proc/<pid>/status for VmRSS
	statusData, err := readProcFile(pid, "status")
	if err != nil {
		return nil, err
	}
	var rssKB float64
	for _, line := range strings.Split(statusData, "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, _ := strconv.ParseFloat(fields[1], 64)
				rssKB = v
			}
			break
		}
	}

	// CPU: two samples separated by 1 second
	st1, t1, err := readProcStat(pid)
	if err != nil {
		return nil, err
	}
	time.Sleep(time.Second)
	st2, t2, err := readProcStat(pid)
	if err != nil {
		return nil, err
	}

	wallTicks := float64(t2-t1) * clkTck()
	procTicks := float64((st2.utime + st2.stime) - (st1.utime + st1.stime))
	cpuPct := 0.0
	if wallTicks > 0 {
		cpuPct = procTicks / wallTicks * 100
	}

	return &ProcStats{
		CPUPct:    cpuPct,
		MemRSSMiB: rssKB / 1024,
	}, nil
}

type procStatFields struct{ utime, stime uint64 }

func readProcStat(pid int) (procStatFields, int64, error) {
	data, err := readProcFile(pid, "stat")
	if err != nil {
		return procStatFields{}, 0, err
	}
	fields := strings.Fields(data)
	if len(fields) < 15 {
		return procStatFields{}, 0, fmt.Errorf("unexpected /proc/stat format")
	}
	utime, _ := strconv.ParseUint(fields[13], 10, 64)
	stime, _ := strconv.ParseUint(fields[14], 10, 64)
	return procStatFields{utime, stime}, time.Now().UnixNano(), nil
}

func readProcFile(pid int, name string) (string, error) {
	data, err := readFile(fmt.Sprintf("/proc/%d/%s", pid, name))
	if err != nil {
		return "", fmt.Errorf("proc %d/%s: %w", pid, name, err)
	}
	return string(data), nil
}

func readFile(path string) ([]byte, error) {
	// minimal implementation — avoids importing "os" separately
	cmd := exec.Command("cat", path)
	out, err := cmd.Output()
	return out, err
}

func clkTck() float64 { return 100 } // HZ, typically 100 on Linux

// ── integrity check ───────────────────────────────────────────────────────────

const integrityPort = 6545
const integrityPayload = 4 * 1024 * 1024 // 4 MB

// checkIntegrity sends 4 MB of random data from src to dst through the overlay
// and verifies the SHA-256 hash matches.
// dst must be the peer's overlay IP.
func checkIntegrity(peerOverlayIP string) (ok bool, err error) {
	// start receiver on peer side via a simple TCP echo check
	// (we use the raw overlay TCP directly — no virlink framing)
	//
	// Approach: connect to integrityPort on peer, send data, compare hash.
	// Requires a lightweight server; since we may not have one, we fall back
	// to verifying data integrity indirectly via the bench (TCP ensures ordering).

	payload := make([]byte, integrityPayload)
	if _, err := rand.Read(payload); err != nil {
		return false, err
	}
	sendHash := sha256.Sum256(payload)

	ln, err := net.Listen("tcp", ":"+strconv.Itoa(integrityPort))
	if err != nil {
		return false, fmt.Errorf("listener: %w", err)
	}
	defer ln.Close()

	var rcvHash [32]byte
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, conn); err != nil && err != io.EOF {
			done <- err
			return
		}
		rcvHash = sha256.Sum256(buf.Bytes())
		done <- nil
	}()

	// dial peer
	conn, err := net.DialTimeout("tcp",
		net.JoinHostPort(peerOverlayIP, strconv.Itoa(integrityPort)),
		10*time.Second)
	if err != nil {
		return false, fmt.Errorf("dial peer: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		conn.Close()
		return false, fmt.Errorf("write: %w", err)
	}
	conn.Close()

	if err := <-done; err != nil {
		return false, fmt.Errorf("receiver: %w", err)
	}
	return sendHash == rcvHash, nil
}
