// tun_tcpmux.go — TCP tunnel with flow-hash multiplexing across parallel streams.
//
// Wire frame (per packet):
//
//	[uint16 BE payload_len][uint32 BE flow_hash][IP packet…]
//
// flow_hash = platform.HashIPPacket(payload) XOR [tcpmux] hash seed.
// Streams are chosen by flow_hash % tcp_streams so each flow stays on one TCP conn.
package tcpmux

import (
	"virlink/internal/wire"
	"virlink/internal/platform"
	"virlink/internal/core"
	"virlink/internal/config"
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
	tcpTxChanCap     = 32
	tcpMuxSubnet     = "10.20.42.0/24"
	tcpMuxHashHdrLen = 4
)

type TcpMuxTunnel struct {
	cfg      *config.Config
	tun      *platform.TunDev
	ln       net.Listener
	conns    [platform.MaxPerfQueues]atomic.Pointer[net.Conn]
	done chan struct{}
	stop     platform.StoppedFlag
	hashSeed uint32
}

func (t *TcpMuxTunnel) DevName() string   { return platform.TunnelDevName(t.cfg, "tcpmux-tun0") }
func (t *TcpMuxTunnel) OverlayIP() string { return core.OverlayAddr(t.cfg, tcpMuxSubnet) }
func (t *TcpMuxTunnel) PeerIP() string    { return core.PeerAddr(t.cfg, tcpMuxSubnet) }

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
	return platform.HashIPPacket([]byte(s))
}

func tcpMuxFlowHash(data []byte, seed uint32) uint32 {
	return platform.HashIPPacket(data) ^ seed
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
		// 1440: wire frame = 1440 + 6 (len+flow_hash platform.Header) = 1446 bytes.
		// Outer TCP MSS with timestamps = 1448 bytes → one wire frame per TCP segment.
		// At 1460 the wire frame (1466) exceeds the outer MSS on most paths, causing
		// each overlay packet to split into two outer TCP segments.
		mtu = 1440
	}
	t.hashSeed = parseTcpMuxHash(c.TcpMux.Hash)
	hashLabel := c.TcpMux.Hash
	if hashLabel == "" {
		hashLabel = "fnv1a"
	}

	platform.Header("tcpmux / " + c.Mode)
	platform.LogInfo(fmt.Sprintf("flow hash multiplex  seed=%s (0x%08x)", hashLabel, t.hashSeed))
	platform.ApplyPerfFromConfig(c)
	platform.Step("perf: " + platform.PerfSummary())
	platform.Step("cleanup...")
	t.doClean()
	t.stop.Reset()

	var err error
	platform.Step(fmt.Sprintf("TUN device %s ×%d queues...", dev, platform.PerfTunQueues()))
	t.tun, err = platform.OpenTunMulti(dev, platform.PerfTunQueues())
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
	platform.LogOK(fmt.Sprintf("%s  %s  MTU=%d  queues=%d", dev, addr, mtu, t.tun.QueueCount()))

	platform.Step(fmt.Sprintf("tuning (%s)...", platform.TuningModeLabel(c)))
	platform.ApplyTunnelTuning(c, dev)

	if err := wire.TcpTunnelWireUp(c); err != nil {
		return err
	}

	platform.AddMSS(c, dev)
	t.done = make(chan struct{})

	tun0 := t.tun.Fd0()
	go t.txPollLoop()

	streams := platform.PerfTcpStreams()
	if c.Mode == "server" {
		t.ln, err = wire.ListenTCPWire(c, port)
		if err != nil {
			return fmt.Errorf("tcpmux listen :%d: %w", port, err)
		}
		platform.LogOK(fmt.Sprintf("TCPmux listening :%d  streams=%d  hash=%s", port, streams, hashLabel))
		go t.acceptLoop(tun0)
	} else {
		go t.connectLoop(tun0)
	}

	platform.Done(dev, addr, peer,
		fmt.Sprintf("transport : TCPmux ×%d streams  hash=%s  :%d", streams, hashLabel, port),
		"frame     : len(2) + flow_hash(4) + IP packet",
		wire.WireTCPDoneExtra(c),
		"reconnect : automatic (client retries every 3 s)",
		"test      : ping -c3 "+peer,
	)
	return nil
}

func (t *TcpMuxTunnel) pickConn(data []byte) net.Conn {
	n := platform.PerfTcpStreams()
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

// txPollLoop reads TUN packets, writes the 6-byte wire platform.Header in-place, and
// dispatches each owned buffer to a per-stream channel. A txMuxStreamWriter
// goroutine per stream accumulates frames into a net.Buffers batch and flushes
// with one writev syscall — no stream-switch penalty, full parallel TX.
func (t *TcpMuxTunnel) txPollLoop() {
	streams := platform.PerfTcpStreams()
	chs := make([]chan []byte, streams)
	for i := range chs {
		chs[i] = make(chan []byte, tcpTxChanCap)
		go t.txMuxStreamWriter(i, chs[i])
	}

	// hdrRoom=6: 2-byte len + 4-byte flow_hash; payload at buf[6:].
	poller := platform.NewTunPollerH(t.tun, &t.stop, 6)
	defer func() {
		poller.Close()
		for _, ch := range chs {
			close(ch)
		}
	}()

	poller.RunOwned(
		nil,
		func(buf []byte, n int) bool {
			platform.StatInc(platform.StatTCPTxRead)
			if n > 0xffff {
				platform.LogDebug(fmt.Sprintf("tcpmux tx: frame too large: %d", n))
				platform.PutBuf(buf)
				return !t.stop.Stopped()
			}
			payload := buf[6 : 6+n]
			// Write 6-byte platform.Header in-place; no payload copy.
			binary.BigEndian.PutUint16(buf[0:2], uint16(n))
			binary.BigEndian.PutUint32(buf[2:6], tcpMuxFlowHash(payload, t.hashSeed))
			slot := tcpMuxSlot(payload, streams, t.hashSeed)

			for i := 0; i < streams; i++ {
				idx := (slot + i) % streams
				select {
				case chs[idx] <- buf:
					return !t.stop.Stopped()
				default:
				}
			}
			// Block on preferred slot — same back-pressure reasoning as tun_tcp.go.
			chs[slot] <- buf
			return !t.stop.Stopped()
		},
	)
}

// txMuxStreamWriter is the per-stream flusher for TCPMUX.
func (t *TcpMuxTunnel) txMuxStreamWriter(slot int, ch <-chan []byte) {
	bsz := platform.PerfBatchSize()
	bufs := make(net.Buffers, 0, bsz)
	pooled := make([][]byte, 0, bsz)
	pollMs := time.Duration(platform.PerfPollMs()) * time.Millisecond

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
			platform.StatInc(platform.StatTCPTxNoConn)
		} else if _, err := bufs.WriteTo(c); err != nil {
			platform.LogDebug(fmt.Sprintf("tcpmux tx stream %d: %v", slot, err))
			t.clearConn(c)
		} else {
			platform.StatAdd(platform.StatTCPTxSend, uint64(len(pooled)))
		}
		for _, b := range pooled {
			platform.PutBuf(b)
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
			if t.stop.Stopped() {
				return
			}
			platform.LogWarn("tcpmux accept: " + err.Error())
			time.Sleep(100 * time.Millisecond)
			continue
		}
		platform.TuneTCPConn(conn)
		idx := slot % platform.PerfTcpStreams()
		slot++
		platform.LogInfo(fmt.Sprintf("tcpmux: client connected from %s (stream %d)", conn.RemoteAddr(), idx))
		t.setConn(idx, conn)
		go t.rxLoop(conn, tun, idx)
	}
}

func (t *TcpMuxTunnel) connectLoop(tun *os.File) {
	for s := 0; s < platform.PerfTcpStreams(); s++ {
		go t.connectOne(tun, s)
	}
	select {
	case <-t.done:
	}
}

func (t *TcpMuxTunnel) connectOne(tun *os.File, slot int) {
	wire.TcpConnectStagger(slot)
	for {
		if t.stop.Stopped() {
			return
		}
		conn, err := wire.DialTCPWire(t.cfg, 10*time.Second)
		if err != nil {
			wire.LogTcpStreamRetry("tcpmux", slot, err)
			select {
			case <-t.done:
				return
			case <-time.After(3 * time.Second):
				continue
			}
		}
		platform.TuneTCPConn(conn)
		wire.NoteTcpWireConnected()
		platform.LogOK(fmt.Sprintf("tcpmux: stream %d up  %s ↔ %s", slot, conn.LocalAddr(), conn.RemoteAddr()))
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
	br := bufio.NewReaderSize(conn, platform.TcpRxBufSize)
	bsz := platform.PerfBatchSize()
	batch := platform.NewTunRxBatch(bsz)

	flush := func() {
		n, err := batch.Flush(tun)
		if n == 0 {
			return
		}
		if err != nil && !t.stop.Stopped() {
			platform.LogWarn("tun write: " + err.Error())
		} else if err == nil {
			platform.StatAdd(platform.StatTCPRxWrite, uint64(n))
		}
	}
	defer flush()

	for {
		frame, n, _, err := tcpMuxReadFrame(br)
		if err != nil {
			if !t.stop.Stopped() {
				platform.LogDebug(fmt.Sprintf("tcpmux rx stream %d: %v", slot, err))
			}
			t.conns[slot].CompareAndSwap(&conn, nil)
			return
		}
		platform.StatInc(platform.StatTCPRxFrame)
		batch.AddOwned(frame, n)
		if batch.Len() >= bsz || br.Buffered() == 0 {
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
	if n == 0 || n > platform.MaxPktBuf {
		return nil, 0, 0, fmt.Errorf("tcpmux invalid frame len %d", n)
	}
	frame = platform.GetBuf()
	if _, err := io.ReadFull(r, frame[:n]); err != nil {
		platform.PutBuf(frame)
		return nil, 0, 0, err
	}
	return frame, n, flow, nil
}

func (t *TcpMuxTunnel) Down() error {
	t.doClean()
	platform.LogOK("tcpmux tunnel torn down")
	return nil
}

func (t *TcpMuxTunnel) doClean() {
	wire.ResetTcpWireConnectState()
	wire.TcpTunnelWireDown(t.cfg)
	platform.RestoreTunnelTuning()
	t.stop.Stop()
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
	platform.DelMSS(t.DevName())
	platform.NlDown(t.DevName())
}

func (t *TcpMuxTunnel) Status() {
	if l, err := netlink.LinkByName(t.DevName()); err == nil {
		fmt.Printf("  %s: flags=%v\n", l.Attrs().Name, l.Attrs().Flags)
	}
	fmt.Printf("  hash: %s (seed=0x%08x)\n", t.cfg.TcpMux.Hash, t.hashSeed)
}
