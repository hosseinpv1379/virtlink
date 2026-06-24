// pool.go — performance helpers shared by all user-space tunnel types.
//
// Performance problems solved here:
//
//  1. Per-packet heap allocation: every loop allocating make([]byte,N) triggers
//     GC on every packet → latency spikes under load. sync.Pool recycles buffers.
//
//  2. Small socket buffers: Linux default SO_RCVBUF is ~208 KB.  At 1 Gbps and
//     1500-byte packets that covers < 1 ms of burst — any hiccup drops packets.
//     We bump all sockets to 4 MB receive + 4 MB send.
//
//  3. TCP Nagle: writing header then payload as two separate syscalls lets Nagle
//     coalesce them into one segment, adding ~40 ms of delay when the window is
//     small.  TCP_NODELAY disables this for tunnel connections.
//
//  4. Vectored I/O: net.Buffers.WriteTo uses writev(2) — header + payload in a
//     single syscall without copying into a new buffer.
package main

import (
	"net"
	"sync"

	"golang.org/x/sys/unix"
)

// ── buffer pool ───────────────────────────────────────────────────────────────
// Packets are at most 65535 bytes (uint16 max).  We add 512 bytes of headroom
// so crypto/framing layers can work in-place without extra allocations.

const maxPktBuf = 65535 + 512

var pktPool = &sync.Pool{
	New: func() interface{} {
		b := make([]byte, maxPktBuf)
		return &b
	},
}

// getBuf returns a buffer from the pool (len == maxPktBuf).
// Always call putBuf when done so the buffer is reused.
func getBuf() []byte { return *pktPool.Get().(*[]byte) }

// putBuf returns b to the pool.  b must have been obtained from getBuf.
func putBuf(b []byte) {
	b = b[:maxPktBuf]
	pktPool.Put(&b)
}

// ── socket tuning ─────────────────────────────────────────────────────────────

// tuneUDPConn sets 4 MB read/write kernel socket buffers on a UDP connection.
// This must be called after Listen/Dial and before any Reads.
// net.core.rmem_max must be ≥ 4 MB (applySysctl sets it to 128 MB).
func tuneUDPConn(conn *net.UDPConn) {
	_ = conn.SetReadBuffer(4 << 20)
	_ = conn.SetWriteBuffer(4 << 20)
}

// tuneRawSock sets 4 MB read/write kernel socket buffers on a raw fd.
func tuneRawSock(fd int) {
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 4<<20)
}

// tuneTCPConn tunes a TCP connection for tunnel use:
//   - TCP_NODELAY:  disable Nagle — critical when framing small packets back-to-back
//   - 4 MB buffers: absorb bursts without head-of-line blocking
func tuneTCPConn(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(4 << 20)
		_ = tc.SetWriteBuffer(4 << 20)
	}
}
