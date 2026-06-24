// pool.go — performance helpers shared by all user-space tunnel types.
package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	maxPktBuf   = 65535 + 512
	sockBufSize = 16 << 20 // 16 MB — absorbs multi-Gbps bursts
	tunWorkers  = 4        // parallel sockets / TCP streams
	icmpHdrLen  = 8
)

var pktPool = sync.Pool{
	New: func() any {
		b := make([]byte, maxPktBuf)
		return &b
	},
}

func getBuf() []byte { return *pktPool.Get().(*[]byte) }
func putBuf(b []byte) {
	b = b[:maxPktBuf]
	pktPool.Put(&b)
}

// icmpFramePool holds reusable [8+maxIP] buffers for ICMP encapsulation.
var icmpFramePool = sync.Pool{
	New: func() any {
		b := make([]byte, icmpHdrLen+maxPktBuf)
		return &b
	},
}

func getICMPFrame() []byte { return *icmpFramePool.Get().(*[]byte) }
func putICMPFrame(b []byte) {
	b = b[:icmpHdrLen+maxPktBuf]
	icmpFramePool.Put(&b)
}

// buildICMPFrame writes an ICMP Echo Request in-place into frame (len ≥ 8+len(payload)).
// Returns the slice to send: frame[:8+payloadLen]. Zero heap allocation.
func buildICMPFrame(frame []byte, id, seq uint16, payload []byte) []byte {
	n := icmpHdrLen + len(payload)
	pkt := frame[:n]
	pkt[0] = 8 // Echo Request
	pkt[1] = 0
	pkt[2] = 0
	pkt[3] = 0
	binary.BigEndian.PutUint16(pkt[4:], id)
	binary.BigEndian.PutUint16(pkt[6:], seq)
	copy(pkt[8:], payload)
	cs := icmpChecksum(pkt)
	binary.BigEndian.PutUint16(pkt[2:], cs)
	return pkt
}

func icmpChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)&1 != 0 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// ── socket tuning ─────────────────────────────────────────────────────────────

func tuneUDPConn(conn *net.UDPConn) {
	_ = conn.SetReadBuffer(sockBufSize)
	_ = conn.SetWriteBuffer(sockBufSize)
}

func tuneRawSock(fd int) {
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, sockBufSize)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, sockBufSize)
}

func tuneTCPConn(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(sockBufSize)
		_ = tc.SetWriteBuffer(sockBufSize)
	}
}

func setSockReusePort(fd int) {
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, sockBufSize)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, sockBufSize)
}

// listenUDPWorkers creates tunWorkers UDP sockets on the same port (SO_REUSEPORT).
func listenUDPWorkers(port int) ([]*net.UDPConn, error) {
	conns := make([]*net.UDPConn, 0, tunWorkers)
	for i := 0; i < tunWorkers; i++ {
		lc := net.ListenConfig{
			Control: func(_ string, _ string, c syscall.RawConn) error {
				return c.Control(func(fd uintptr) { setSockReusePort(int(fd)) })
			},
		}
		pc, err := lc.ListenPacket(context.Background(), "udp4", portAddr(port))
		if err != nil {
			for _, c := range conns {
				c.Close()
			}
			return nil, err
		}
		conns = append(conns, pc.(*net.UDPConn))
	}
	return conns, nil
}

// dialUDPWorkers opens tunWorkers UDP sockets to the same remote endpoint.
func dialUDPWorkers(remoteIP string, port int) ([]*net.UDPConn, error) {
	conns := make([]*net.UDPConn, 0, tunWorkers)
	for i := 0; i < tunWorkers; i++ {
		lc := net.ListenConfig{
			Control: func(_ string, _ string, c syscall.RawConn) error {
				return c.Control(func(fd uintptr) { setSockReusePort(int(fd)) })
			},
		}
		pc, err := lc.ListenPacket(context.Background(), "udp4", ":0")
		if err != nil {
			for _, c := range conns {
				c.Close()
			}
			return nil, err
		}
		uc := pc.(*net.UDPConn)
		tuneUDPConn(uc)
		conns = append(conns, uc)
	}
	return conns, nil
}

func portAddr(port int) string {
	return fmt.Sprintf(":%d", port)
}

// openRawICMPWorkers creates tunWorkers raw ICMP sockets with SO_REUSEPORT.
func openRawICMPWorkers() ([]int, error) {
	fds := make([]int, 0, tunWorkers)
	for i := 0; i < tunWorkers; i++ {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
		if err != nil {
			for _, f := range fds {
				unix.Close(f)
			}
			return nil, err
		}
		setSockReusePort(fd)
		tuneRawSock(fd)
		fds = append(fds, fd)
	}
	return fds, nil
}

func closeFDs(fds []int) {
	for _, fd := range fds {
		if fd > 0 {
			unix.Close(fd)
		}
	}
}

func closeUDPs(conns []*net.UDPConn) {
	for _, c := range conns {
		if c != nil {
			c.Close()
		}
	}
}

// rrCounter round-robin index for multi-socket TX.
type rrCounter struct{ n atomic.Uint32 }

func (r *rrCounter) next() int { return int(r.n.Add(1)-1) % tunWorkers }

// stoppedFlag is checked occasionally in hot loops (no select per packet).
type stoppedFlag struct{ v atomic.Bool }

func (s *stoppedFlag) stop()     { s.v.Store(true) }
func (s *stoppedFlag) stopped() bool { return s.v.Load() }
