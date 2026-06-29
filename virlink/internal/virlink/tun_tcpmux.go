// tun_tcpmux.go — TCP tunnel with flow-hash multiplexing across parallel streams.
//
// Wire frame (per packet):
//
//	[uint16 BE payload_len][uint32 BE flow_hash][IP packet…]
//
// flow_hash = hashIPPacket(payload) XOR [tcpmux] hash seed.
// Streams are chosen by flow_hash % tcp_streams so each flow stays on one TCP conn.
package virlink

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vishvananda/netlink"
)

const (
	tcpMuxSubnet     = "10.20.42.0/24"
	tcpMuxHashHdrLen = 4
)

type TcpMuxTunnel struct {
	cfg      *Config
	tun      *TunDev
	ln       net.Listener
	conns    [maxPerfQueues]atomic.Pointer[net.Conn]
	done     chan struct{}
	stop     stoppedFlag
	hashSeed uint32
}

func (t *TcpMuxTunnel) DevName() string   { return tunnelDevName(t.cfg, "tcpmux-tun0") }
func (t *TcpMuxTunnel) OverlayIP() string { return overlayAddr(t.cfg, tcpMuxSubnet) }
func (t *TcpMuxTunnel) PeerIP() string    { return peerAddr(t.cfg, tcpMuxSubnet) }

func parseTcpMuxHash(s string) uint32 {
	s = strings.TrimSpace(strings.ToLower(s))
	switch s {
	case "", "fnv1a", "fnv-1a", "fnv":
		return 0
	}
	if strings.HasPrefix(s, "0x") {
		if v, err := strconv.ParseUint(s[2:], 16, 32); err == nil {
			return uint32(v)
		}
	}
	if v, err := strconv.ParseUint(s, 10, 32); err == nil {
		return uint32(v)
	}
	return hashIPPacket([]byte(s))
}

func tcpMuxFlowHash(data []byte, seed uint32) uint32 {
	return hashIPPacket(data) ^ seed
}

func tcpMuxSlot(data []byte, streams int, seed uint32) int {
	if streams <= 1 {
		return 0
	}
	return int(tcpMuxFlowHash(data, seed) % uint32(streams))
}

func (t *TcpMuxTunnel) Up() error {
	c := t.cfg
	dev := t.DevName()
	addr := t.OverlayIP()
	peer := t.PeerIP()
	port := c.Transport.Port
	mtu := c.Tunnel.MTU
	if mtu == 0 {
		mtu = 1460
	}
	t.hashSeed = parseTcpMuxHash(c.TcpMux.Hash)
	hashLabel := c.TcpMux.Hash
	if hashLabel == "" {
		hashLabel = "fnv1a"
	}

	header("tcpmux / " + c.Mode)
	logInfo(fmt.Sprintf("flow hash multiplex  seed=%s (0x%08x)", hashLabel, t.hashSeed))
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

	addMSS(dev)
	t.done = make(chan struct{})

	tun0 := t.tun.Fd0()
	go t.txPollLoop()

	streams := perfTcpStreams()
	if c.Mode == "server" {
		t.ln, err = listenTCPWire(c, port)
		if err != nil {
			return fmt.Errorf("tcpmux listen :%d: %w", port, err)
		}
		logOK(fmt.Sprintf("TCPmux listening :%d  streams=%d  hash=%s", port, streams, hashLabel))
		go t.acceptLoop(tun0)
	} else {
		go t.connectLoop(tun0)
	}

	done(dev, addr, peer,
		fmt.Sprintf("transport : TCPmux ×%d streams  hash=%s  :%d", streams, hashLabel, port),
		"frame     : len(2) + flow_hash(4) + IP packet",
		wireTCPDoneExtra(c),
		"reconnect : automatic (client retries every 3 s)",
		"test      : ping -c3 "+peer,
	)
	return nil
}

func (t *TcpMuxTunnel) pickConn(data []byte) net.Conn {
	n := perfTcpStreams()
	slot := tcpMuxSlot(data, n, t.hashSeed)
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

// txPollLoop reads TUN packets, writes the 6-byte wire header in-place, and
// dispatches each owned buffer to a per-stream channel. A txMuxStreamWriter
// goroutine per stream accumulates frames into a net.Buffers batch and flushes
// with one writev syscall — no stream-switch penalty, full parallel TX.
func (t *TcpMuxTunnel) txPollLoop() {
	streams := perfTcpStreams()
	chs := make([]chan []byte, streams)
	for i := range chs {
		chs[i] = make(chan []byte, tcpTxChanCap)
		go t.txMuxStreamWriter(i, chs[i])
	}

	// hdrRoom=6: 2-byte len + 4-byte flow_hash; payload at buf[6:].
	poller := newTunPollerH(t.tun, &t.stop, 6)
	defer func() {
		poller.close()
		for _, ch := range chs {
			close(ch)
		}
	}()

	poller.RunOwned(
		nil,
		func(buf []byte, n int) bool {
			statInc(statTCPTxRead)
			if n > 0xffff {
				logDebug(fmt.Sprintf("tcpmux tx: frame too large: %d", n))
				putBuf(buf)
				return !t.stop.stopped()
			}
			payload := buf[6 : 6+n]
			// Write 6-byte header in-place; no payload copy.
			binary.BigEndian.PutUint16(buf[0:2], uint16(n))
			binary.BigEndian.PutUint32(buf[2:6], tcpMuxFlowHash(payload, t.hashSeed))
			slot := tcpMuxSlot(payload, streams, t.hashSeed)

			for i := 0; i < streams; i++ {
				idx := (slot + i) % streams
				select {
				case chs[idx] <- buf:
					return !t.stop.stopped()
				default:
				}
			}
			statInc(statTCPTxNoConn)
			putBuf(buf)
			return !t.stop.stopped()
		},
	)
}

// txMuxStreamWriter is the per-stream flusher for TCPMUX.
func (t *TcpMuxTunnel) txMuxStreamWriter(slot int, ch <-chan []byte) {
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
			logDebug(fmt.Sprintf("tcpmux tx stream %d: %v", slot, err))
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
			n := int(binary.BigEndian.Uint16(buf[0:2]))
			bufs = append(bufs, buf[:tcpMuxHashHdrLen+2+n])
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

func (t *TcpMuxTunnel) clearConn(c net.Conn) {
	for i := range t.conns {
		if p := t.conns[i].Load(); p != nil && *p == c {
			_ = c.Close()
			t.conns[i].Store(nil)
			return
		}
	}
}

func (t *TcpMuxTunnel) setConn(slot int, c net.Conn) {
	if old := t.conns[slot].Swap(&c); old != nil && *old != c {
		_ = (*old).Close()
	}
}

func (t *TcpMuxTunnel) acceptLoop(tun *os.File) {
	slot := 0
	for {
		conn, err := t.ln.Accept()
		if err != nil {
			if t.stop.stopped() {
				return
			}
			logWarn("tcpmux accept: " + err.Error())
			time.Sleep(100 * time.Millisecond)
			continue
		}
		tuneTCPConn(conn)
		idx := slot % perfTcpStreams()
		slot++
		logInfo(fmt.Sprintf("tcpmux: client connected from %s (stream %d)", conn.RemoteAddr(), idx))
		t.setConn(idx, conn)
		go t.rxLoop(conn, tun, idx)
	}
}

func (t *TcpMuxTunnel) connectLoop(tun *os.File) {
	for s := 0; s < perfTcpStreams(); s++ {
		go t.connectOne(tun, s)
	}
	select {
	case <-t.done:
	}
}

func (t *TcpMuxTunnel) connectOne(tun *os.File, slot int) {
	tcpConnectStagger(slot)
	for {
		if t.stop.stopped() {
			return
		}
		conn, err := dialTCPWire(t.cfg, 10*time.Second)
		if err != nil {
			logTcpStreamRetry("tcpmux", slot, err)
			select {
			case <-t.done:
				return
			case <-time.After(3 * time.Second):
				continue
			}
		}
		tuneTCPConn(conn)
		noteTcpWireConnected()
		logOK(fmt.Sprintf("tcpmux: stream %d up  %s ↔ %s", slot, conn.LocalAddr(), conn.RemoteAddr()))
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

func (t *TcpMuxTunnel) rxLoop(conn net.Conn, tun *os.File, slot int) {
	defer conn.Close()
	br := bufio.NewReaderSize(conn, tcpRxBufSize)
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
		frame, n, _, err := tcpMuxReadFrame(br)
		if err != nil {
			if !t.stop.stopped() {
				logDebug(fmt.Sprintf("tcpmux rx stream %d: %v", slot, err))
			}
			t.conns[slot].CompareAndSwap(&conn, nil)
			return
		}
		statInc(statTCPRxFrame)
		batch.addOwned(frame, n)
		if batch.len() >= bsz || br.Buffered() == 0 {
			flush()
		}
	}
}

func tcpMuxReadFrame(r io.Reader) (frame []byte, n int, flow uint32, err error) {
	var hdr [6]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, 0, 0, err
	}
	n = int(binary.BigEndian.Uint16(hdr[0:2]))
	flow = binary.BigEndian.Uint32(hdr[2:6])
	if n == 0 || n > maxPktBuf {
		return nil, 0, 0, fmt.Errorf("tcpmux invalid frame len %d", n)
	}
	frame = getBuf()
	if _, err := io.ReadFull(r, frame[:n]); err != nil {
		putBuf(frame)
		return nil, 0, 0, err
	}
	return frame, n, flow, nil
}

func (t *TcpMuxTunnel) Down() error {
	t.doClean()
	logOK("tcpmux tunnel torn down")
	return nil
}

func (t *TcpMuxTunnel) doClean() {
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

func (t *TcpMuxTunnel) Status() {
	if l, err := netlink.LinkByName(t.DevName()); err == nil {
		fmt.Printf("  %s: flags=%v\n", l.Attrs().Name, l.Attrs().Flags)
	}
	fmt.Printf("  hash: %s (seed=0x%08x)\n", t.cfg.TcpMux.Hash, t.hashSeed)
}
