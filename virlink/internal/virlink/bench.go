// bench.go — multi-stream, time-based in-tunnel bandwidth test.
//
// Follows speedtest.net convention:
//   DOWNLOAD = data flowing FROM peer TO us  (we measure RX throughput)
//   UPLOAD   = data flowing FROM us TO peer  (we measure TX throughput)
//
// Order: download first, then upload (standard speedtest order).
//
// Each test: benchStreams parallel TCP connections, each runs for
// benchDuration seconds.  Timing starts after the TCP handshake so
// connection setup overhead is excluded from the measurement.
//
// Server listens on 0.0.0.0:benchPort (healthPort+1, default 6544).
package virlink

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	benchDuration  = 5 * time.Second  // test duration per direction
	benchStreams    = 4                // parallel TCP connections
	benchBufSize   = 256 * 1024       // 256 KB per-stream buffer
	benchSockBuf   = 4 * 1024 * 1024  // 4 MB socket buffer
	benchCacheTTL  = 2 * time.Minute  // cache result to avoid back-to-back runs

	modeSend byte = 0x01 // server → client  (client measures DOWNLOAD)
	modeRecv byte = 0x02 // client → server  (client measures UPLOAD)
)

// BenchResult holds one complete measurement.
type BenchResult struct {
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

// BenchMgr manages the benchmark server + test runs.
type BenchMgr struct {
	port      int
	peerIP    string
	overlayIP string

	mu         sync.Mutex
	running    bool
	lastResult *BenchResult
	lastRun    time.Time
}

func NewBenchMgr(healthPort int, peerIP, overlayIP string) *BenchMgr {
	return &BenchMgr{port: healthPort + 1, peerIP: peerIP, overlayIP: overlayIP}
}

func tuneBenchConn(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(benchSockBuf)
		_ = tc.SetWriteBuffer(benchSockBuf)
		_ = tc.SetNoDelay(false) // Nagle ON — better for bulk throughput
	}
}

// ── benchmark server ──────────────────────────────────────────────────────────

func (b *BenchMgr) runServer() {
	bindIP := b.overlayIP
	if bindIP == "" {
		bindIP = "0.0.0.0"
	}
	addr := fmt.Sprintf("%s:%d", bindIP, b.port)
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		logWarn(fmt.Sprintf("bench server: listen %s: %v", addr, err))
		return
	}
	logInfo(fmt.Sprintf("bench  server   listen=%s  (healthPort+1)", addr))
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go b.serveConn(conn)
	}
}

func (b *BenchMgr) serveConn(conn net.Conn) {
	defer conn.Close()
	tuneBenchConn(conn)
	// generous deadline: mode byte + test duration + overhead
	_ = conn.SetDeadline(time.Now().Add(benchDuration + 15*time.Second))

	hdr := make([]byte, 1)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}

	switch hdr[0] {
	case modeSend:
		// Server sends data → client measures DOWNLOAD
		buf := make([]byte, benchBufSize)
		start := time.Now()
		var sent int64
		for time.Now().Before(start.Add(benchDuration)) {
			n, err := conn.Write(buf)
			sent += int64(n)
			if err != nil {
				break
			}
		}
		// send server-side TX speed back (8 bytes)
		rep := make([]byte, 8)
		bps := uint64(0)
		if elapsed := time.Since(start).Seconds(); elapsed > 0 {
			bps = uint64(float64(sent) / elapsed)
		}
		binary.BigEndian.PutUint64(rep, bps)
		_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		_, _ = conn.Write(rep)

	case modeRecv:
		// Server receives data → client measures UPLOAD
		start := time.Now()
		n, _ := io.Copy(io.Discard, conn)
		elapsed := time.Since(start).Seconds()
		// send server-side RX speed back (8 bytes, informational)
		rep := make([]byte, 8)
		bps := uint64(0)
		if elapsed > 0 {
			bps = uint64(float64(n) / elapsed)
		}
		binary.BigEndian.PutUint64(rep, bps)
		_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		_, _ = conn.Write(rep)
	}
}

// ── DOWNLOAD: server sends → we receive ──────────────────────────────────────

func (b *BenchMgr) measureDownload() (mbPerSec float64, err error) {
	type result struct {
		bytes int64
		dur   time.Duration
		err   error
	}
	results := make([]result, benchStreams)
	var wg sync.WaitGroup

	for i := 0; i < benchStreams; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			addr := fmt.Sprintf("%s:%d", b.peerIP, b.port)
			conn, cerr := net.DialTimeout("tcp4", addr, 10*time.Second)
			if cerr != nil {
				results[idx].err = cerr
				return
			}
			defer conn.Close()
			tuneBenchConn(conn)

			// Send mode byte — timing starts AFTER this
			if _, cerr = conn.Write([]byte{modeSend}); cerr != nil {
				results[idx].err = cerr
				return
			}

			// Measure: read data for benchDuration
			testDeadline := time.Now().Add(benchDuration + 1*time.Second)
			_ = conn.SetReadDeadline(testDeadline)

			buf := make([]byte, benchBufSize)
			var received int64
			start := time.Now()
			for time.Now().Before(testDeadline.Add(-500*time.Millisecond)) {
				n, rerr := conn.Read(buf)
				received += int64(n)
				if rerr != nil {
					break
				}
			}
			results[idx].bytes = received
			results[idx].dur = time.Since(start)
		}(i)
	}
	wg.Wait()

	var totalBytes int64
	var totalDur time.Duration
	for _, r := range results {
		if r.err != nil {
			return 0, r.err
		}
		totalBytes += r.bytes
		if r.dur > totalDur {
			totalDur = r.dur
		}
	}
	elapsed := totalDur.Seconds()
	if elapsed <= 0 || totalBytes == 0 {
		return 0, fmt.Errorf("no data received")
	}
	return float64(totalBytes) / elapsed / (1024 * 1024), nil
}

// ── UPLOAD: we send → server receives ────────────────────────────────────────

func (b *BenchMgr) measureUpload() (mbPerSec float64, err error) {
	type result struct {
		bytes int64
		dur   time.Duration
		err   error
	}
	results := make([]result, benchStreams)
	var wg sync.WaitGroup

	for i := 0; i < benchStreams; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			addr := fmt.Sprintf("%s:%d", b.peerIP, b.port)
			conn, cerr := net.DialTimeout("tcp4", addr, 10*time.Second)
			if cerr != nil {
				results[idx].err = cerr
				return
			}
			defer conn.Close()
			tuneBenchConn(conn)

			if _, cerr = conn.Write([]byte{modeRecv}); cerr != nil {
				results[idx].err = cerr
				return
			}

			// Send data for benchDuration — timing starts AFTER mode byte
			sendEnd := time.Now().Add(benchDuration)
			_ = conn.SetWriteDeadline(sendEnd.Add(1 * time.Second))

			buf := make([]byte, benchBufSize)
			var sent int64
			start := time.Now()
			for time.Now().Before(sendEnd) {
				n, werr := conn.Write(buf)
				sent += int64(n)
				if werr != nil {
					break
				}
			}
			results[idx].bytes = sent
			results[idx].dur = time.Since(start)

			// Read server ack (best-effort, non-blocking)
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, _ = io.ReadFull(conn, make([]byte, 8))
		}(i)
	}
	wg.Wait()

	var totalBytes int64
	var totalDur time.Duration
	for _, r := range results {
		if r.err != nil {
			return 0, r.err
		}
		totalBytes += r.bytes
		if r.dur > totalDur {
			totalDur = r.dur
		}
	}
	elapsed := totalDur.Seconds()
	if elapsed <= 0 || totalBytes == 0 {
		return 0, fmt.Errorf("no data sent")
	}
	return float64(totalBytes) / elapsed / (1024 * 1024), nil
}

// ── RunBench ──────────────────────────────────────────────────────────────────

func (b *BenchMgr) RunBench() *BenchResult {
	b.mu.Lock()
	if !b.lastRun.IsZero() && time.Since(b.lastRun) < benchCacheTTL && b.lastResult != nil {
		res := b.lastResult
		b.mu.Unlock()
		return res
	}
	if b.running {
		b.mu.Unlock()
		// wait for running test to finish
		for i := 0; i < int((benchDuration*2+5*time.Second)/time.Second); i++ {
			time.Sleep(time.Second)
			b.mu.Lock()
			if !b.running && b.lastResult != nil {
				res := b.lastResult
				b.mu.Unlock()
				return res
			}
			b.mu.Unlock()
		}
		return nil
	}
	b.running = true
	b.mu.Unlock()

	totalStart := time.Now()
	res := &BenchResult{
		Streams:      benchStreams,
		TestDuration: benchDuration.String(),
	}

	logInfo(fmt.Sprintf("bench  start  streams=%d  duration=%s  peer=%s:%d",
		benchStreams, benchDuration, b.peerIP, b.port))

	// ── 1. DOWNLOAD (speedtest order: download first) ──
	dlMBs, dlErr := b.measureDownload()
	if dlErr != nil {
		res.Error = "download: " + dlErr.Error()
		goto done
	}
	res.DownloadMBs = round2(dlMBs)
	res.DownloadMbps = round2(dlMBs * 8)
	logInfo(fmt.Sprintf("bench  download  %.2f MB/s  (%.2f Mbps)", res.DownloadMBs, res.DownloadMbps))

	// ── 2. UPLOAD ──
	if ulMBs, ulErr := b.measureUpload(); ulErr != nil {
		res.Error = "upload: " + ulErr.Error()
	} else {
		res.UploadMBs = round2(ulMBs)
		res.UploadMbps = round2(ulMBs * 8)
		logInfo(fmt.Sprintf("bench  upload    %.2f MB/s  (%.2f Mbps)", res.UploadMBs, res.UploadMbps))
	}

done:
	res.TotalDuration = time.Since(totalStart).Round(time.Millisecond).String()
	res.TestedAt = time.Now().Format("2006-01-02 15:04:05")

	b.mu.Lock()
	b.lastResult = res
	b.lastRun = time.Now()
	b.running = false
	b.mu.Unlock()

	logInfo(fmt.Sprintf("bench  done  ↓download=%.2f Mbps  ↑upload=%.2f Mbps  total=%s",
		res.DownloadMbps, res.UploadMbps, res.TotalDuration))
	return res
}

func round2(f float64) float64 {
	return float64(int64(f*100+0.5)) / 100
}

// atomic helper used by the parallel goroutines
var _ = atomic.Int64{}
