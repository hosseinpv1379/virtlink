// bench.go — multi-stream, time-based in-tunnel bandwidth test.
//
// Design goals (maximum throughput accuracy):
//   • Time-based (not size-based): run for benchDuration seconds so TCP
//     windows fully open and throughput stabilises regardless of link speed.
//   • Parallel streams: benchStreams concurrent TCP connections saturate
//     tunnels where a single flow can't fill the pipe (GRE-FOU, bonded, etc.).
//   • Large buffers: 256 KB per stream, socket buffers tuned to 4 MB.
//   • Symmetric: upload and download tested independently.
//
// Server listens on 0.0.0.0:benchPort (default 6544) /TCP.
// All traffic flows through the tunnel overlay IPs → measures real link BW.
//
// Protocol:
//   connection → 1-byte mode:
//     0x01 upload   client sends until deadline → server drains
//     0x02 download server sends until deadline → client drains
//   After upload, server replies 8 bytes = its measured RX speed (bytes/s).
package main

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
	benchDuration = 5 * time.Second // test duration per direction
	benchStreams   = 4               // parallel TCP connections
	benchBufSize   = 256 * 1024     // 256 KB write/read buffer per stream
	benchSockBuf   = 4 * 1024 * 1024 // 4 MB socket buffer
	benchCacheTTL  = 2 * time.Minute

	modeUpload   byte = 0x01
	modeDownload byte = 0x02
)

// BenchResult holds one complete measurement.
type BenchResult struct {
	UploadMbps    float64 `json:"upload_mbps"`
	DownloadMbps  float64 `json:"download_mbps"`
	UploadMBs     float64 `json:"upload_mb_s"`
	DownloadMBs   float64 `json:"download_mb_s"`
	Streams       int     `json:"streams"`
	TestDuration  string  `json:"test_duration"`
	TotalDuration string  `json:"total_duration"`
	TestedAt      string  `json:"tested_at"`
	Error         string  `json:"error,omitempty"`
}

// BenchMgr manages the benchmark server + test runs.
type BenchMgr struct {
	port   int
	peerIP string

	mu         sync.Mutex
	running    bool
	lastResult *BenchResult
	lastRun    time.Time
}

func NewBenchMgr(healthPort int, peerIP string) *BenchMgr {
	return &BenchMgr{port: healthPort + 1, peerIP: peerIP}
}

// ── socket tuning helpers ─────────────────────────────────────────────────────

func tuneBenchConn(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(benchSockBuf)
		_ = tc.SetWriteBuffer(benchSockBuf)
		_ = tc.SetNoDelay(false) // nagle ON for bulk throughput (opposite of low-latency)
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
		go b.serveConn(conn)
	}
}

func (b *BenchMgr) serveConn(conn net.Conn) {
	defer conn.Close()
	tuneBenchConn(conn)
	_ = conn.SetDeadline(time.Now().Add(benchDuration + 10*time.Second))

	mode := make([]byte, 1)
	if _, err := io.ReadFull(conn, mode); err != nil {
		return
	}

	switch mode[0] {
	case modeUpload:
		// drain incoming data, report server-side speed
		start := time.Now()
		n, _ := io.Copy(io.Discard, conn)
		elapsed := time.Since(start).Seconds()
		var bps uint64
		if elapsed > 0 {
			bps = uint64(float64(n) / elapsed)
		}
		rep := make([]byte, 8)
		binary.BigEndian.PutUint64(rep, bps)
		_, _ = conn.Write(rep)

	case modeDownload:
		// stream data until the client closes or deadline fires
		buf := make([]byte, benchBufSize)
		for {
			if _, err := conn.Write(buf); err != nil {
				break
			}
		}
	}
}

// ── multi-stream upload measurement ──────────────────────────────────────────

// measureUpload opens benchStreams parallel connections, sends for benchDuration,
// returns aggregate throughput in MB/s.
func (b *BenchMgr) measureUpload() (mbPerSec float64, err error) {
	var totalBytes atomic.Int64
	var wg sync.WaitGroup
	errs := make([]error, benchStreams)
	deadline := time.Now().Add(benchDuration)

	for i := 0; i < benchStreams; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			addr := fmt.Sprintf("%s:%d", b.peerIP, b.port)
			conn, cerr := net.DialTimeout("tcp4", addr, 10*time.Second)
			if cerr != nil {
				errs[idx] = cerr
				return
			}
			defer conn.Close()
			tuneBenchConn(conn)
			_ = conn.SetDeadline(deadline.Add(5 * time.Second))

			if _, cerr = conn.Write([]byte{modeUpload}); cerr != nil {
				errs[idx] = cerr
				return
			}

			buf := make([]byte, benchBufSize)
			var sent int64
			for time.Now().Before(deadline) {
				n, werr := conn.Write(buf)
				sent += int64(n)
				if werr != nil {
					break
				}
			}
			totalBytes.Add(sent)

			// read server ack (best-effort)
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			_, _ = io.ReadFull(conn, make([]byte, 8))
		}(i)
	}

	start := time.Now()
	wg.Wait()
	elapsed := time.Since(start).Seconds()

	for _, e := range errs {
		if e != nil {
			return 0, e
		}
	}
	if elapsed <= 0 || totalBytes.Load() == 0 {
		return 0, fmt.Errorf("no data transferred")
	}
	return float64(totalBytes.Load()) / elapsed / (1024 * 1024), nil
}

// ── multi-stream download measurement ────────────────────────────────────────

func (b *BenchMgr) measureDownload() (mbPerSec float64, err error) {
	var totalBytes atomic.Int64
	var wg sync.WaitGroup
	errs := make([]error, benchStreams)
	deadline := time.Now().Add(benchDuration)

	for i := 0; i < benchStreams; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			addr := fmt.Sprintf("%s:%d", b.peerIP, b.port)
			conn, cerr := net.DialTimeout("tcp4", addr, 10*time.Second)
			if cerr != nil {
				errs[idx] = cerr
				return
			}
			defer conn.Close()
			tuneBenchConn(conn)
			_ = conn.SetDeadline(deadline.Add(2 * time.Second))

			if _, cerr = conn.Write([]byte{modeDownload}); cerr != nil {
				errs[idx] = cerr
				return
			}

			buf := make([]byte, benchBufSize)
			var received int64
			for time.Now().Before(deadline) {
				_ = conn.SetReadDeadline(deadline)
				n, rerr := conn.Read(buf)
				received += int64(n)
				if rerr != nil {
					break
				}
			}
			totalBytes.Add(received)
		}(i)
	}

	start := time.Now()
	wg.Wait()
	elapsed := time.Since(start).Seconds()

	for _, e := range errs {
		if e != nil {
			return 0, e
		}
	}
	if elapsed <= 0 || totalBytes.Load() == 0 {
		return 0, fmt.Errorf("no data received")
	}
	return float64(totalBytes.Load()) / elapsed / (1024 * 1024), nil
}

// ── RunBench — orchestrates upload + download, caches result ─────────────────

func (b *BenchMgr) RunBench() *BenchResult {
	b.mu.Lock()
	if !b.lastRun.IsZero() && time.Since(b.lastRun) < benchCacheTTL && b.lastResult != nil {
		res := b.lastResult
		b.mu.Unlock()
		return res
	}
	if b.running {
		b.mu.Unlock()
		// poll until done (max 2× benchDuration)
		for i := 0; i < int(benchDuration*2/time.Second); i++ {
			time.Sleep(time.Second)
			b.mu.Lock()
			if !b.running {
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

	uplMBs, uplErr := b.measureUpload()
	if uplErr != nil {
		res.Error = "upload: " + uplErr.Error()
		goto done
	}
	res.UploadMBs = round2(uplMBs)
	res.UploadMbps = round2(uplMBs * 8)
	logInfo(fmt.Sprintf("bench  upload   %.2f MB/s  (%.2f Mbps)", res.UploadMBs, res.UploadMbps))

	if dlMBs, dlErr := b.measureDownload(); dlErr != nil {
		res.Error = "download: " + dlErr.Error()
	} else {
		res.DownloadMBs = round2(dlMBs)
		res.DownloadMbps = round2(dlMBs * 8)
		logInfo(fmt.Sprintf("bench  download %.2f MB/s  (%.2f Mbps)", res.DownloadMBs, res.DownloadMbps))
	}

done:
	res.TotalDuration = time.Since(totalStart).Round(time.Millisecond).String()
	res.TestedAt = time.Now().Format("2006-01-02 15:04:05")

	b.mu.Lock()
	b.lastResult = res
	b.lastRun = time.Now()
	b.running = false
	b.mu.Unlock()

	logInfo(fmt.Sprintf("bench  done    upload=%.2f Mbps  download=%.2f Mbps  took=%s",
		res.UploadMbps, res.DownloadMbps, res.TotalDuration))
	return res
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}
