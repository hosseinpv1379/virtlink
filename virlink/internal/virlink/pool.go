// pool.go — performance helpers shared by all user-space tunnel types.
package virlink

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

const (
	maxPktBuf  = 65535 + 512
	icmpHdrLen = 8
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

// icmpFramePool holds reusable buffers for ICMP encapsulation (+ optional IPv4 header).
var icmpFramePool = sync.Pool{
	New: func() any {
		b := make([]byte, ipHdrLen+icmpHdrLen+maxPktBuf)
		return &b
	},
}

func getICMPFrame() []byte { return *icmpFramePool.Get().(*[]byte) }
func putICMPFrame(b []byte) {
	b = b[:ipHdrLen+icmpHdrLen+maxPktBuf]
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
	_ = conn.SetReadBuffer(perfSockBuf())
	_ = conn.SetWriteBuffer(perfSockBuf())
}

func tuneRawSock(fd int) {
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, perfSockBuf())
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, perfSockBuf())
}

func tuneTCPConn(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(perfSockBuf())
		_ = tc.SetWriteBuffer(perfSockBuf())
	}
}

// udpConnFD returns the underlying socket fd for sendmmsg batching.
func udpConnFD(conn *net.UDPConn) (int, error) {
	f, err := conn.File()
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return int(f.Fd()), nil
}

// openRawICMP creates one raw ICMP socket (no SO_REUSEPORT — duplicates packets).
func openRawICMP() (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
	if err != nil {
		return 0, err
	}
	tuneRawSock(fd)
	return fd, nil
}

// connectUDP binds the socket to a fixed peer (fewer lookups per send).
func connectUDP(conn *net.UDPConn, dst *net.UDPAddr) error {
	f, err := conn.File()
	if err != nil {
		return err
	}
	defer f.Close()
	sa := &unix.SockaddrInet4{Port: dst.Port}
	copy(sa.Addr[:], dst.IP.To4())
	return unix.Connect(int(f.Fd()), sa)
}

func closeFDs(fds []int) {
	for _, fd := range fds {
		if fd > 0 {
			unix.Close(fd)
		}
	}
}

// rrCounter round-robin index for multi-stream TX.
type rrCounter struct{ n atomic.Uint32 }

func (r *rrCounter) next(mod int) int { return int(r.n.Add(1)-1) % mod }

// atomicSeqDedup — lock-free outer ICMP sequence dedup (no mutex in hot path).
type atomicSeqDedup struct {
	slots [4096]atomic.Uint32
}

func (d *atomicSeqDedup) dup(seq uint16) bool {
	idx := uint32(seq) & 4095
	tag := (uint32(seq) << 16) | 1 // +1 so empty slot (0) never matches seq=0
	for {
		old := d.slots[idx].Load()
		if old != 0 && old>>16 == uint32(seq) {
			return true
		}
		if d.slots[idx].CompareAndSwap(old, tag) {
			return false
		}
	}
}

func (d *atomicSeqDedup) reset() {
	for i := range d.slots {
		d.slots[i].Store(0)
	}
}

// ipPktDedup — lock-free dedup by inner IP packet hash.
// 4096 slots = 32 KB; enough for any realistic in-flight window.
type ipPktDedup struct {
	slots [4096]atomic.Uint64
}

func hashIPPacket(p []byte) uint32 {
	// FNV-1a over first 40 bytes (covers IP+TCP/UDP headers — sufficient for dedup).
	h := uint32(2166136261)
	n := len(p)
	if n > 40 {
		n = 40
	}
	for i := 0; i < n; i++ {
		h ^= uint32(p[i])
		h *= 16777619
	}
	if h == 0 {
		h = 1
	}
	return h
}

func (d *ipPktDedup) dup(p []byte) bool {
	if len(p) < 20 {
		return false
	}
	hash := hashIPPacket(p)
	idx := hash & 4095
	tag := (uint64(hash) << 16) | 1
	for {
		old := d.slots[idx].Load()
		if old != 0 && uint32(old>>16) == hash {
			return true
		}
		if d.slots[idx].CompareAndSwap(old, tag) {
			return false
		}
	}
}

func (d *ipPktDedup) reset() {
	for i := range d.slots {
		d.slots[i].Store(0)
	}
}

// stoppedFlag is checked occasionally in hot loops (no select per packet).
type stoppedFlag struct{ v atomic.Bool }

func (s *stoppedFlag) stop()         { s.v.Store(true) }
func (s *stoppedFlag) reset()        { s.v.Store(false) }
func (s *stoppedFlag) stopped() bool { return s.v.Load() }

// ipTo4 parses an IPv4 address into a fixed [4]byte (zero if invalid).
func ipTo4(s string) [4]byte {
	var out [4]byte
	ip := net.ParseIP(s)
	if ip == nil {
		return out
	}
	copy(out[:], ip.To4())
	return out
}

// acquireTunnelLock prevents two virlink processes from running the same tunnel.
func acquireTunnelLock(dev string) (*os.File, error) {
	dir := "/var/run/virlink"
	_ = os.MkdirAll(dir, 0o755)
	path := dir + "/" + dev + ".lock"
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another virlink instance is already running (%s) — stop it first", dev)
	}
	return f, nil
}

func releaseTunnelLock(f *os.File) {
	if f == nil {
		return
	}
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	f.Close()
}
