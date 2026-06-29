// tun_tcp.go — TCP tunnel.
//
// Performance (v2.7): multi-queue TUN tx readers + parallel TCP streams ([tuning] tcp_streams).
package virlink

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/vishvananda/netlink"
)

const tcpSubnet = "10.20.41.0/24"

type TcpTunnel struct {
	cfg    *Config
	tun    *TunDev
	ln     net.Listener
	conns  [maxPerfQueues]atomic.Pointer[net.Conn]
	done   chan struct{}
	stop   stoppedFlag
}

func (t *TcpTunnel) DevName() string   { return tunnelDevName(t.cfg, "tcp-tun0") }
func (t *TcpTunnel) OverlayIP() string { return overlayAddr(t.cfg, tcpSubnet) }
func (t *TcpTunnel) PeerIP() string    { return peerAddr(t.cfg, tcpSubnet) }

func (t *TcpTunnel) Up() error {
	c := t.cfg
	dev := t.DevName()
	addr := t.OverlayIP()
	peer := t.PeerIP()
	port := c.Transport.Port
	mtu := c.Tunnel.MTU
	if mtu == 0 {
		// 1440: wire frame = 1440 + 2 (len header) = 1442 bytes.
		// Outer TCP MSS with timestamps = 1448 bytes → one wire frame per TCP segment.
		// At 1460 the wire frame (1462) exceeds the MSS on many paths (PPPoE, timestamps),
		// causing each overlay packet to split into two outer TCP segments.
		mtu = 1440
	}

	header("tcp / " + c.Mode)
	applyPerfFromConfig(c)
	step("perf: " + perfSummary())
	step("cleanup...")
	t.doClean()
	t.stop.reset()

	var err error
	step(fmt.Sprintf("TUN device %s ×%d queues...", dev, perfTunQueues()))
	t.tun, err = openTunMulti(dev, perfTunQueues())
	if err != nil {
		return fmt.Errorf("tun: %w", err)
	}
	l, err := netlink.LinkByName(dev)
	if err != nil {
		return fmt.Errorf("link %s: %w", dev, err)
	}
	if err := netlink.LinkSetMTU(l, mtu); err != nil {
		return fmt.Errorf("mtu: %w", err)
	}
	a, _ := netlink.ParseAddr(addr)
	if err := netlink.AddrAdd(l, a); err != nil {
		return fmt.Errorf("addr: %w", err)
	}
	if err := netlink.LinkSetUp(l); err != nil {
		return fmt.Errorf("link up: %w", err)
	}
	logOK(fmt.Sprintf("%s  %s  MTU=%d  queues=%d", dev, addr, mtu, t.tun.QueueCount()))

	step(fmt.Sprintf("tuning (%s)...", tuningModeLabel(c)))
	applyTunnelTuning(c, dev)

	if err := tcpTunnelWireUp(c); err != nil {
		return err
	}

	addMSS(c, dev)
	t.done = make(chan struct{})

	tun0 := t.tun.Fd0()
	go t.txPollLoop()

	streams := perfTcpStreams()
	if c.Mode == "server" {
		t.ln, err = listenTCPWire(c, port)
		if err != nil {
			return fmt.Errorf("tcp listen :%d: %w", port, err)
		}
		logOK(fmt.Sprintf("TCP listening %s  streams=%d", t.ln.Addr(), streams))
		go t.acceptLoop(tun0)
	} else {
		go t.connectLoop(tun0)
	}

	done(dev, addr, peer,
		fmt.Sprintf("transport : TCP ×%d streams  poller×1 :%d", streams, port),
		wireTCPDoneExtra(c),
		"reconnect : automatic (client retries every 3 s)",
		"test      : ping -c3 "+peer,
	)
	return nil
}

func tcpStreamSlot(data []byte, streams int) int {
	if streams <= 1 {
		return 0
	}
	return int(hashIPPacket(data) % uint32(streams))
}

func (t *TcpTunnel) pickConn(data []byte) net.Conn {
	n := perfTcpStreams()
	slot := tcpStreamSlot(data, n)
	if c := t.conns[slot].Load(); c != nil {
		return *c
	}
	for i := 0; i < n; i++ {
		if c := t.conns[i].Load(); c != nil {
			return *c
		}
	}
	return nil
}

// tcpTxChanCap is the per-stream TX channel capacity.
// 32 slots × ~1442 bytes ≈ 46 KB per stream.
// Together with TCP_NOTSENT_LOWAT (64 KB), total unsent buffering per stream
// is ~110 KB — enough to keep the wire saturated (≥ BDP for most VPN paths)
// without hiding congestion from the inner TCP.
const tcpTxChanCap = 32

// txPollLoop reads TUN packets and dispatches them into per-stream buffered
// channels. Each stream runs its own txStreamWriter goroutine that accumulates
// frames into a net.Buffers batch and flushes with a single writev syscall.
//
// This replaces the old "flush on stream-switch" design: each stream writer
// can fill a full batch independently, and writers for different streams
// run concurrently on separate goroutines.
func (t *TcpTunnel) txPollLoop() {
	streams := perfTcpStreams()
	chs := make([]chan []byte, streams)
	for i := range chs {
		chs[i] = make(chan []byte, tcpTxChanCap)
		go t.txStreamWriter(i, chs[i])
	}

	// hdrRoom=2: poller reads TUN packet into buf[2:], leaving buf[0:2] for
	// the length header — no payload copy on dispatch.
	poller := newTunPollerH(t.tun, &t.stop, 2)
	defer func() {
		poller.close()
		for _, ch := range chs {
			close(ch)
		}
	}()

	poller.RunOwned(
		nil, // stream writers handle their own flush timers
		func(buf []byte, n int) bool {
			statInc(statTCPTxRead)
			payload := buf[2 : 2+n]
			binary.BigEndian.PutUint16(buf[:2], uint16(n))
			slot := tcpStreamSlot(payload, streams)

			// Try the preferred slot first, then any other — non-blocking.
			for i := 0; i < streams; i++ {
				idx := (slot + i) % streams
				select {
				case chs[idx] <- buf:
					return !t.stop.stopped()
				default:
				}
			}
			// All channels full: BLOCK on preferred slot instead of dropping.
			// Blocking stops the TUN poller, which fills the kernel TUN ring,
			// which causes the inner TCP to reduce its CWND — proper back-pressure.
			// Dropping would cause inner TCP retransmits with no congestion signal.
			// TCP_NOTSENT_LOWAT ensures this only triggers when the outer TCP wire
			// is genuinely saturated, not due to kernel send-buffer bloat.
			chs[slot] <- buf
			return !t.stop.stopped()
		},
	)
}

// txStreamWriter flushes one TCP stream. It reads from ch, accumulates frames
// into a net.Buffers batch, and writes via a single writev syscall when the
// batch is full or the flush timer fires.
func (t *TcpTunnel) txStreamWriter(slot int, ch <-chan []byte) {
	bsz := perfBatchSize()
	bufs := make(net.Buffers, 0, bsz)
	pooled := make([][]byte, 0, bsz)
	pollMs := time.Duration(perfPollMs()) * time.Millisecond

	flush := func() {
		if len(pooled) == 0 {
			return
		}
		var c net.Conn
		if p := t.conns[slot].Load(); p != nil {
			c = *p
		} else {
			// Fallback: use any available stream.
			for i := range t.conns {
				if p := t.conns[i].Load(); p != nil {
					c = *p
					break
				}
			}
		}
		if c == nil {
			statInc(statTCPTxNoConn)
		} else if _, err := bufs.WriteTo(c); err != nil {
			logDebug(fmt.Sprintf("tcp tx stream %d: %v", slot, err))
			t.clearConn(c)
		} else {
			statAdd(statTCPTxSend, uint64(len(pooled)))
		}
		for _, b := range pooled {
			putBuf(b)
		}
		bufs = bufs[:0]
		pooled = pooled[:0]
	}

	timer := time.NewTimer(pollMs)
	defer timer.Stop()

	for {
		select {
		case buf, ok := <-ch:
			if !ok {
				flush()
				return
			}
			n := int(binary.BigEndian.Uint16(buf[:2]))
			bufs = append(bufs, buf[:2+n])
			pooled = append(pooled, buf)
			if len(pooled) >= bsz {
				flush()
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(pollMs)
			}
		case <-timer.C:
			flush()
			timer.Reset(pollMs)
		}
	}
}

func (t *TcpTunnel) clearConn(c net.Conn) {
	for i := range t.conns {
		if p := t.conns[i].Load(); p != nil && *p == c {
			_ = c.Close()
			t.conns[i].Store(nil)
			return
		}
	}
}

func (t *TcpTunnel) setConn(slot int, c net.Conn) {
	if old := t.conns[slot].Swap(&c); old != nil && *old != c {
		_ = (*old).Close()
	}
}

func (t *TcpTunnel) acceptLoop(tun *os.File) {
	slot := 0
	for {
		conn, err := t.ln.Accept()
		if err != nil {
			if t.stop.stopped() {
				return
			}
			logWarn("tcp accept: " + err.Error())
			time.Sleep(100 * time.Millisecond)
			continue
		}
		tuneTCPConn(conn)
		idx := slot % perfTcpStreams()
		logInfo(fmt.Sprintf("[wire] tcp accept stream %d  wire peer=%s",
			idx, conn.RemoteAddr()))
		slot++
		t.setConn(idx, conn)
		go t.rxLoop(conn, tun, idx)
	}
}

func (t *TcpTunnel) connectLoop(tun *os.File) {
	for s := 0; s < perfTcpStreams(); s++ {
		go t.connectOne(tun, s)
	}
	select {
	case <-t.done:
	}
}

func (t *TcpTunnel) connectOne(tun *os.File, slot int) {
	tcpConnectStagger(slot)
	for {
		if t.stop.stopped() {
			return
		}
		conn, err := dialTCPWire(t.cfg, 10*time.Second)
		if err != nil {
			logTcpStreamRetry("tcp", slot, err)
			select {
			case <-t.done:
				return
			case <-time.After(3 * time.Second):
				continue
			}
		}
		tuneTCPConn(conn)
		noteTcpWireConnected()
		logOK(fmt.Sprintf("tcp: stream %d up  %s ↔ %s", slot, conn.LocalAddr(), conn.RemoteAddr()))
		t.setConn(slot, conn)
		t.rxLoop(conn, tun, slot)
		t.conns[slot].Store(nil)
		select {
		case <-t.done:
			return
		case <-time.After(time.Second):
		}
	}
}

func (t *TcpTunnel) rxLoop(conn net.Conn, tun *os.File, slot int) {
	defer conn.Close()
	br := bufio.NewReaderSize(conn, tcpRxBufSize)
	var hdr [2]byte
	bsz := perfBatchSize()
	batch := newTunRxBatch(bsz)

	flush := func() {
		n, err := batch.flush(tun)
		if n == 0 {
			return
		}
		if err != nil && !t.stop.stopped() {
			logWarn("tun write: " + err.Error())
		} else if err == nil {
			statAdd(statTCPRxWrite, uint64(n))
		}
	}
	defer flush()

	for {
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			if !t.stop.stopped() {
				logDebug(fmt.Sprintf("tcp rx stream %d: %v", slot, err))
			}
			t.conns[slot].CompareAndSwap(&conn, nil)
			return
		}
		n := int(binary.BigEndian.Uint16(hdr[:]))
		if n == 0 || n > maxPktBuf {
			logWarn(fmt.Sprintf("tcp rx: invalid frame len %d", n))
			return
		}
		frame := getBuf()
		if _, err := io.ReadFull(br, frame[:n]); err != nil {
			putBuf(frame)
			if !t.stop.stopped() {
				logDebug(fmt.Sprintf("tcp rx read stream %d: %v", slot, err))
			}
			return
		}
		statInc(statTCPRxFrame)
		batch.addOwned(frame, n)
		if batch.len() >= bsz || br.Buffered() == 0 {
			flush()
		}
	}
}

func (t *TcpTunnel) Down() error {
	t.doClean()
	logOK("tcp tunnel torn down")
	return nil
}

func (t *TcpTunnel) doClean() {
	resetTcpWireConnectState()
	tcpTunnelWireDown(t.cfg)
	restoreTunnelTuning()
	t.stop.stop()
	if t.done != nil {
		select {
		case <-t.done:
		default:
			close(t.done)
		}
		t.done = nil
	}
	if t.ln != nil {
		_ = t.ln.Close()
		t.ln = nil
	}
	for i := range t.conns {
		if p := t.conns[i].Load(); p != nil {
			_ = (*p).Close()
			t.conns[i].Store(nil)
		}
	}
	if t.tun != nil {
		t.tun.Close()
		t.tun = nil
	}
	delMSS(t.DevName())
	nlDown(t.DevName())
}

func (t *TcpTunnel) Status() {
	if l, err := netlink.LinkByName(t.DevName()); err == nil {
		fmt.Printf("  %s: flags=%v\n", l.Attrs().Name, l.Attrs().Flags)
	}
}
