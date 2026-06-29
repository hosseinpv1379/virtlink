//go:build linux

// batch_linux.go — sendmmsg batching for ICMP TX (linux only).
package virlink

import (
	"net"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const icmpBatchMax = maxPerfBatch

type mmsghdr struct {
	Hdr unix.Msghdr
	Len uint32
	_   [4]byte
}

func sendmmsg(fd int, msgs []mmsghdr) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	n, _, e := unix.Syscall6(unix.SYS_SENDMMSG,
		uintptr(fd),
		uintptr(unsafe.Pointer(&msgs[0])),
		uintptr(len(msgs)), 0, 0, 0)
	if e != 0 {
		return 0, e
	}
	return int(n), nil
}

func recvmmsg(fd int, msgs []mmsghdr, flags int) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	n, _, e := unix.Syscall6(unix.SYS_RECVMMSG,
		uintptr(fd),
		uintptr(unsafe.Pointer(&msgs[0])),
		uintptr(len(msgs)),
		uintptr(flags), 0, 0)
	if e != 0 {
		return int(n), e
	}
	return int(n), nil
}

// rxMmsgBatch receives up to nbufs datagrams per recvmmsg syscall (wire/UDP RX).
type rxMmsgBatch struct {
	nbufs int
	bufs  [icmpBatchMax][]byte
	iovs  [icmpBatchMax]unix.Iovec
	addrs [icmpBatchMax]unix.RawSockaddrInet4
	msgs  [icmpBatchMax]mmsghdr
}

func (b *rxMmsgBatch) init(n int) {
	if n < 1 {
		n = 1
	}
	if n > icmpBatchMax {
		n = icmpBatchMax
	}
	b.nbufs = n
	for i := 0; i < n; i++ {
		if b.bufs[i] == nil {
			b.bufs[i] = getBuf()
		}
		b.iovs[i].Base = &b.bufs[i][0]
		b.iovs[i].Len = uint64(len(b.bufs[i]))
		b.msgs[i].Hdr.Iov = &b.iovs[i]
		b.msgs[i].Hdr.Iovlen = 1
		b.msgs[i].Hdr.Name = (*byte)(unsafe.Pointer(&b.addrs[i]))
		b.msgs[i].Hdr.Namelen = unix.SizeofSockaddrInet4
		b.msgs[i].Len = 0
	}
}

func (b *rxMmsgBatch) release() {
	for i := 0; i < icmpBatchMax; i++ {
		if b.bufs[i] != nil {
			putBuf(b.bufs[i])
			b.bufs[i] = nil
		}
	}
}

// recv drains up to nbufs packets with one recvmmsg (MSG_DONTWAIT).
// msg_namelen must be reset before every recvmmsg — the kernel overwrites it
// on return and subsequent receives fail silently if it is stale.
func (b *rxMmsgBatch) recv(fd int) (int, error) {
	for i := 0; i < b.nbufs; i++ {
		b.msgs[i].Hdr.Namelen = unix.SizeofSockaddrInet4
	}
	return recvmmsg(fd, b.msgs[:b.nbufs], unix.MSG_DONTWAIT)
}

func (b *rxMmsgBatch) data(i int) []byte {
	return b.bufs[i][:b.msgs[i].Len]
}

func (b *rxMmsgBatch) from4(i int) *unix.SockaddrInet4 {
	return &unix.SockaddrInet4{Addr: b.addrs[i].Addr}
}

// installICMPFilter drops all ICMP types except echo request (type 8) at the socket.
func installICMPFilter(fd int) error {
	var filter [32]byte // 256 types
	for t := 0; t < 256; t++ {
		if t != icmpEchoReq {
			filter[t/8] |= 1 << (t % 8)
		}
	}
	return unix.SetsockoptString(fd, unix.IPPROTO_ICMP, unix.ICMP_FILTER, string(filter[:]))
}

// icmpWireCarrierType returns the ICMP type byte for a raw RX buffer, or 255 if unknown.
func icmpWireCarrierType(pkt []byte, wireOn bool) byte {
	pkt = trimIPv4Packet(pkt)
	icmp, ok := parseIcmpWirePacket(pkt, wireOn)
	if !ok || len(icmp) == 0 {
		return 255
	}
	return icmp[0]
}

func tunWritev(fd *os.File, bufs [][]byte) error {
	if len(bufs) == 0 {
		return nil
	}
	if len(bufs) == 1 {
		_, err := fd.Write(bufs[0])
		return err
	}
	_, err := unix.Writev(int(fd.Fd()), bufs)
	return err
}

// tunRxBatch accumulates inbound (wire → TUN) packets so a burst of datagrams
// drained from one rx loop iteration costs one tunWritev instead of one
// Write per packet. Payloads are copied into pooled buffers since the rx
// loop's read buffer is reused for the next recvfrom before the batch flushes.
type tunRxBatch struct {
	bufs   [][]byte
	pooled [][]byte
}

// newTunRxBatch pre-allocates slice backing arrays sized to cap so the first
// append in a burst loop does not trigger a runtime growth allocation.
func newTunRxBatch(cap int) tunRxBatch {
	return tunRxBatch{
		bufs:   make([][]byte, 0, cap),
		pooled: make([][]byte, 0, cap),
	}
}

func (b *tunRxBatch) add(payload []byte) {
	frame := getBuf()
	n := copy(frame, payload)
	b.bufs = append(b.bufs, frame[:n])
	b.pooled = append(b.pooled, frame)
}

// addOwned takes ownership of frame (already filled); avoids an extra copy on TCP RX.
func (b *tunRxBatch) addOwned(frame []byte, n int) {
	b.bufs = append(b.bufs, frame[:n])
	b.pooled = append(b.pooled, frame)
}

func (b *tunRxBatch) len() int { return len(b.bufs) }

// flush writes the batch in one tunWritev call and returns the packet count
// that was flushed (0 if the batch was already empty).
func (b *tunRxBatch) flush(tun *os.File) (int, error) {
	n := len(b.bufs)
	if n == 0 {
		return 0, nil
	}
	err := tunWritev(tun, b.bufs)
	for _, p := range b.pooled {
		putBuf(p)
	}
	b.bufs = b.bufs[:0]
	b.pooled = b.pooled[:0]
	return n, err
}

// icmpTxBatch holds up to icmpBatchMax frames ready for sendmmsg.
type icmpTxBatch struct {
	n      int
	frames [icmpBatchMax][]byte
	lens   [icmpBatchMax]int
	ports  [icmpBatchMax]uint16 // host order; 0 for raw IP sockets
	iovs   [icmpBatchMax]unix.Iovec
	addrs  [icmpBatchMax]unix.RawSockaddrInet4
	msgs   [icmpBatchMax]mmsghdr
}

func (b *icmpTxBatch) reset() { b.n = 0 }

func (b *icmpTxBatch) add(frame []byte, pktLen int, dst [4]byte, port uint16) {
	i := b.n
	b.frames[i] = frame
	b.lens[i] = pktLen
	b.ports[i] = port
	portBE := port
	if port != 0 {
		portBE = (port << 8) | (port >> 8)
	}
	b.addrs[i] = unix.RawSockaddrInet4{Family: unix.AF_INET, Port: portBE, Addr: dst}
	b.iovs[i].Base = &frame[0]
	b.iovs[i].Len = uint64(pktLen)
	b.msgs[i].Hdr.Name = (*byte)(unsafe.Pointer(&b.addrs[i]))
	b.msgs[i].Hdr.Namelen = unix.SizeofSockaddrInet4
	b.msgs[i].Hdr.Iov = &b.iovs[i]
	b.msgs[i].Hdr.Iovlen = 1
	b.n++
}

// mmsgSendBatch sends batched raw/UDP frames via sendmmsg; falls back to Sendto per packet.
// Returns the number of packets that failed to send.
func mmsgSendBatch(rawFd int, b *icmpTxBatch) int {
	if b.n == 0 {
		return 0
	}
	errs := 0
	sent, err := sendmmsg(rawFd, b.msgs[:b.n])
	if err != nil && sent <= 0 {
		sent = 0
	}
	for i := sent; i < b.n; i++ {
		sa := &unix.SockaddrInet4{Addr: b.addrs[i].Addr}
		if p := b.ports[i]; p != 0 {
			sa.Port = int(p)
		}
		if e := unix.Sendto(rawFd, b.frames[i][:b.lens[i]], 0, sa); e != nil && e != unix.EAGAIN {
			errs++
		}
	}
	return errs
}

// icmpSendBatch is an alias for mmsgSendBatch (ICMP TX path).
func icmpSendBatch(rawFd int, b *icmpTxBatch) int { return mmsgSendBatch(rawFd, b) }

// tuneTCPConnForce sets TCP socket buffers using SO_RCVBUFFORCE / SO_SNDBUFFORCE,
// which bypass net.core.rmem_max / wmem_max (require CAP_NET_ADMIN / root).
// Falls back to the regular SO_RCVBUF / SO_SNDBUF on EPERM.
func tuneTCPConnForce(tc *net.TCPConn) {
	sc, err := tc.SyscallConn()
	if err != nil {
		_ = tc.SetReadBuffer(perfSockBuf())
		_ = tc.SetWriteBuffer(perfSockBuf())
		return
	}
	bufSize := perfSockBuf()
	_ = sc.Control(func(fd uintptr) {
		if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, bufSize); e != nil {
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, bufSize)
		}
		if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, bufSize); e != nil {
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, bufSize)
		}
	})
}
