// bench.go — in-tunnel bandwidth test (upload + download through overlay).
//
// Both sides run a benchmark server on benchPort = healthPort+1 (default 6544).
// The server listens on 0.0.0.0:benchPort/TCP.
// All test traffic flows through the tunnel overlay IPs, measuring real throughput.
//
// Protocol (simple, stateless):
//   Client connects to peerOverlay:benchPort/TCP
//   Sends 1-byte mode header:
//     0x01 = upload   → client sends testBytes, server drains and replies 8-byte speed
//     0x02 = download → server sends testBytes, client drains and measures
//
// GET /bench on the health HTTP server triggers both tests and returns JSON.
// Results are cached for cacheTTL to avoid hammering the tunnel.
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	benchTestMB  = 10                        // MB per direction
	benchTestSize = benchTestMB * 1024 * 1024 // bytes
	benchCacheTTL = 2 * time.Minute
	modeUpload   byte = 0x01 // client→server
	modeDownload byte = 0x02 // server→client
)

// BenchResult holds a completed measurement.
type BenchResult struct {
	UploadMbps   float64 `json:"upload_mbps"`
	DownloadMbps float64 `json:"download_mbps"`
	UploadMBs    float64 `json:"upload_mb_s"`
	DownloadMBs  float64 `json:"download_mb_s"`
	DataSizeMB   int     `json:"data_size_mb"`
	Duration     string  `json:"duration"`
	TestedAt     string  `json:"tested_at"`
	Error        string  `json:"error,omitempty"`
}

// BenchMgr manages the benchmark server + client tests.
type BenchMgr struct {
	port    int    // benchPort = healthPort+1
	peerIP  string // peer overlay IP

	mu       sync.Mutex
	running  bool
	lastResult *BenchResult
	lastRun    time.Time
}

func NewBenchMgr(healthPort int, peerIP string) *BenchMgr {
	return &BenchMgr{
		port:   healthPort + 1,
		peerIP: peerIP,
	}
}

// ── benchmark server ──────────────────────────────────────────────────────────

func (b *BenchMgr) runServer() {
	addr := fmt.Sprintf(":%d", b.port)
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		logWarn(fmt.Sprintf("bench server: listen %s: %v", addr, err))
		return
	}
	logInfo(fmt.Sprintf("bench  server       listen=0.0.0.0:%d  GET /bench", b.port))
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go b.handleConn(conn)
	}
}

func (b *BenchMgr) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))

	// read 1-byte mode
	mode := make([]byte, 1)
	if _, err := io.ReadFull(conn, mode); err != nil {
		return
	}

	switch mode[0] {
	case modeUpload:
		// drain bytes coming from peer, measure server-side rx speed
		start := time.Now()
		n, _ := io.Copy(io.Discard, conn)
		elapsed := time.Since(start).Seconds()
		var bps uint64
		if elapsed > 0 {
			bps = uint64(float64(n) / elapsed)
		}
		// send back 8-byte rx speed (bytes/s)
		result := make([]byte, 8)
		binary.BigEndian.PutUint64(result, bps)
		_, _ = conn.Write(result)

	case modeDownload:
		// send benchTestSize bytes to peer
		buf := make([]byte, 64*1024)
		remaining := int64(benchTestSize)
		for remaining > 0 {
			n := int64(len(buf))
			if n > remaining {
				n = remaining
			}
			written, err := conn.Write(buf[:n])
			remaining -= int64(written)
			if err != nil {
				break
			}
		}
	}
}

// ── benchmark client (runs in HTTP handler goroutine) ─────────────────────────

// RunBench performs upload+download tests and caches the result.
// Thread-safe; concurrent calls wait for the running test.
func (b *BenchMgr) RunBench() *BenchResult {
	b.mu.Lock()
	// return cached result if fresh
	if !b.lastRun.IsZero() && time.Since(b.lastRun) < benchCacheTTL && b.lastResult != nil {
		res := b.lastResult
		b.mu.Unlock()
		return res
	}
	// already running — wait and return last
	if b.running {
		b.mu.Unlock()
		time.Sleep(100 * time.Millisecond)
		b.mu.Lock()
		res := b.lastResult
		b.mu.Unlock()
		return res
	}
	b.running = true
	b.mu.Unlock()

	start := time.Now()
	res := &BenchResult{DataSizeMB: benchTestMB}

	uplMBs, uplErr := b.measureUpload()
	if uplErr != nil {
		res.Error = "upload: " + uplErr.Error()
		goto done
	}
	res.UploadMBs = uplMBs
	res.UploadMbps = uplMBs * 8

	if dlMBs, dlErr := b.measureDownload(); dlErr != nil {
		res.Error = "download: " + dlErr.Error()
	} else {
		res.DownloadMBs = dlMBs
		res.DownloadMbps = dlMBs * 8
	}

done:
	res.Duration = time.Since(start).Round(time.Millisecond).String()
	res.TestedAt = time.Now().Format("2006-01-02 15:04:05")

	b.mu.Lock()
	b.lastResult = res
	b.lastRun = time.Now()
	b.running = false
	b.mu.Unlock()
	return res
}

func (b *BenchMgr) measureUpload() (mbPerSec float64, err error) {
	addr := fmt.Sprintf("%s:%d", b.peerIP, b.port)
	conn, err := net.DialTimeout("tcp4", addr, 10*time.Second)
	if err != nil {
		return 0, fmt.Errorf("connect: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))

	// send mode
	if _, err = conn.Write([]byte{modeUpload}); err != nil {
		return 0, fmt.Errorf("write mode: %v", err)
	}

	// send test data, measure client-side throughput
	buf := make([]byte, 64*1024)
	remaining := int64(benchTestSize)
	sent := int64(0)
	txStart := time.Now()
	for remaining > 0 {
		n := int64(len(buf))
		if n > remaining {
			n = remaining
		}
		w, werr := conn.Write(buf[:n])
		sent += int64(w)
		remaining -= int64(w)
		if werr != nil {
			break
		}
	}
	txElapsed := time.Since(txStart).Seconds()

	// read server-side measurement (8 bytes)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reply := make([]byte, 8)
	if _, rerr := io.ReadFull(conn, reply); rerr == nil {
		serverBps := float64(binary.BigEndian.Uint64(reply))
		_ = serverBps // can log later
	}

	if txElapsed <= 0 || sent == 0 {
		return 0, fmt.Errorf("no data sent")
	}
	return float64(sent) / txElapsed / (1024 * 1024), nil
}

func (b *BenchMgr) measureDownload() (mbPerSec float64, err error) {
	addr := fmt.Sprintf("%s:%d", b.peerIP, b.port)
	conn, err := net.DialTimeout("tcp4", addr, 10*time.Second)
	if err != nil {
		return 0, fmt.Errorf("connect: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))

	if _, err = conn.Write([]byte{modeDownload}); err != nil {
		return 0, fmt.Errorf("write mode: %v", err)
	}

	rxStart := time.Now()
	n, _ := io.Copy(io.Discard, conn)
	rxElapsed := time.Since(rxStart).Seconds()

	if rxElapsed <= 0 || n == 0 {
		return 0, fmt.Errorf("no data received")
	}
	return float64(n) / rxElapsed / (1024 * 1024), nil
}

// ── HTTP /bench handler ───────────────────────────────────────────────────────

func benchHTTPHandler(bm *BenchMgr) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if bm == nil {
			http.Error(w, `{"error":"bench disabled"}`, http.StatusServiceUnavailable)
			return
		}
		// run benchmark (may block up to ~60s on first call or after cache expiry)
		res := bm.RunBench()

		code := http.StatusOK
		if res != nil && res.Error != "" {
			code = http.StatusInternalServerError
		}

		if res != nil {
			logInfo(fmt.Sprintf("bench  result  upload=%.2f Mbps  download=%.2f Mbps  duration=%s",
				res.UploadMbps, res.DownloadMbps, res.Duration))
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(res)
	}
}
