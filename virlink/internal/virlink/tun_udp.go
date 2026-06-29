// tun_udp.go — plain UDP tunnel.
//
// Performance: multi-queue TUN, sendmmsg TX batching, tuned socket buffers.
package virlink

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const udpRawSubnet = "10.20.42.0/24"

type UdpTunnel struct {
	cfg       *Config
	tun       *TunDev
	udpConn   *net.UDPConn
	rawFd     int
	lockFd    *os.File
	done      chan struct{}
	stop      stoppedFlag
	lastPeer  atomic.Value
	lastRoute atomic.Value
	wire      wireSpoof
	peerIP    [4]byte
	localIP   [4]byte
}

func (t *UdpTunnel) DevName() string   { return tunnelDevName(t.cfg, "udp-tun0") }
func (t *UdpTunnel) OverlayIP() string { return overlayAddr(t.cfg, udpRawSubnet) }
func (t *UdpTunnel) PeerIP() string    { return peerAddr(t.cfg, udpRawSubnet) }

func (t *UdpTunnel) Up() error {
	c := t.cfg
	dev := t.DevName()
	addr := t.OverlayIP()
	peer := t.PeerIP()
	port := c.Transport.Port
	mtu := c.Tunnel.MTU
	if mtu == 0 {
		mtu = 1472
	}
	t.peerIP = ipTo4(c.RemoteIP)
	t.localIP = ipTo4(c.LocalIP)
	t.wire = wireSpoofFrom(c)
	if c.Mode == "server" {
		t.lastRoute.Store(t.peerIP)
	}

	header("udp / " + c.Mode)
	applyPerfFromConfig(c)
	step("perf: " + perfSummary())
	t.doClean()
	t.stop.reset()

	var err error
	t.lockFd, err = acquireTunnelLock(dev)
	if err != nil {
		return err
	}

	t.tun, err = openTunMulti(dev, perfTunQueues())
	if err != nil {
		return fmt.Errorf("tun: %w", err)
	}
	l, _ := netlink.LinkByName(dev)
	netlink.LinkSetMTU(l, mtu)
	a, _ := netlink.ParseAddr(addr)
	netlink.AddrAdd(l, a)
	netlink.LinkSetUp(l)
	logOK(fmt.Sprintf("%s  %s  queues=%d", dev, addr, t.tun.QueueCount()))

	step(fmt.Sprintf("tuning (%s)...", tuningModeLabel(c)))
	applyTunnelTuning(c, dev)

	if t.wire.on {
		t.rawFd, err = openRawWire()
		if err != nil {
			return fmt.Errorf("SOCK_RAW udp: %w", err)
		}
		_ = unix.SetNonblock(t.rawFd, true)
		logOK(fmt.Sprintf("raw UDP (IPPROTO_RAW) :%d", port))
		logWireSpoof(t.cfg, t.wire)
	} else {
		t.udpConn, err = net.ListenUDP("udp4", &net.UDPAddr{Port: port})
		if err != nil {
			return fmt.Errorf("udp :%d: %w", port, err)
		}
		tuneUDPConn(t.udpConn)
		if c.Mode == "client" {
			dst := &net.UDPAddr{IP: net.ParseIP(c.RemoteIP), Port: port}
			t.lastPeer.Store(dst)
		}
		logOK(fmt.Sprintf("UDP :%d", port))
	}

	addMSS(c, dev)
	t.done = make(chan struct{})

	if t.wire.on {
		rawFd := t.rawFd
		go t.rxLoopRaw(rawFd, t.tun.WriteFd(), port)
		go t.txPollLoopRaw(rawFd, port)
	} else {
		conn := t.udpConn
		go t.rxLoop(conn, t.tun.WriteFd())
		go t.txPollLoop(conn)
	}

	done(dev, addr, peer, fmt.Sprintf("transport : UDP :%d  poller×1", port))
	return nil
}

func (t *UdpTunnel) rxLoopRaw(rawFd int, tun *os.File, port int) {
	var rb rxMmsgBatch
	rb.init(perfBatchSize())
	defer rb.release()

	peer := t.wire.wirePeer(t.peerIP)
	local := t.localIP
	pollMs := perfPollMs()
	idleMs := pollMs
	bsz := perfBatchSize()
	batch := newTunRxBatch(bsz)

	flush := func() {
		n, err := batch.flush(tun)
		if n == 0 {
			return
		}
		if err != nil {
			statInc(statUDPRxDropWrite)
			if !t.stop.stopped() {
				logDiagOnce("udp:tun_write", 15*time.Second,
					fmt.Sprintf("UDP TUN write failed: %v (%d pkt dropped)", err, n))
			}
		} else {
			statAdd(statUDPRxWrite, uint64(n))
		}
	}
	defer flush()

	for {
		got, err := rb.recv(rawFd)
		if got == 0 {
			if t.stop.stopped() {
				return
			}
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == nil {
				flush()
				_ = pollFD(rawFd, unix.POLLIN, idleMs)
				idleMs = idleBackoff(idleMs, pollMs)
				continue
			}
			if err == unix.EINTR {
				continue
			}
			logWarn("udp rx: " + err.Error())
			continue
		}
		idleMs = pollMs
		for i := 0; i < got; i++ {
			pkt := rb.data(i)
			sa := rb.from4(i)
			if !acceptWirePeer(pkt, sa, local, peer, t.wire.src, t.wire, unix.IPPROTO_UDP) {
				statInc(statUDPRxDrop)
				continue
			}
			ihl, ok := parseIPv4Payload(pkt)
			if !ok {
				continue
			}
			n := len(pkt)
			if n < ihl+udpHdrLen {
				continue
			}
			if int(binary.BigEndian.Uint16(pkt[ihl+2:])) != port {
				statInc(statUDPRxDrop)
				if wireMonitorActive() {
					sport := binary.BigEndian.Uint16(pkt[ihl:])
					var src [4]byte
					copy(src[:], pkt[12:16])
					logWarn(fmt.Sprintf("[wire] RX drop bad_udp_port sport=%d want=%d outer src=%s",
						sport, port, ip4Fmt(src)))
				}
				continue
			}
			payload := pkt[ihl+udpHdrLen : n]
			if t.cfg.Mode == "server" {
				t.lastRoute.Store(rememberPeerRoute(t.wire, sa.Addr, t.peerIP))
			}
			statInc(statUDPRxRecv)
			NoteTunnelAlive()
			batch.add(payload)
		}
		if batch.len() >= bsz {
			flush()
		}
	}
}

func (t *UdpTunnel) txPollLoopRaw(rawFd int, port int) {
	poller := newTunPoller(t.tun, &t.stop)
	defer poller.close()

	var batch icmpTxBatch
	bsz := perfBatchSize()
	var curDst [4]byte
	var haveDst bool
	var lastPLen int

	flush := func() {
		if batch.n == 0 {
			return
		}
		statAdd(statUDPTxSend, uint64(batch.n))
		nerr := mmsgSendBatch(rawFd, &batch)
		if t.wire.on {
			sent := batch.n - nerr
			if sent < 0 {
				sent = 0
			}
			wireMon.noteTxBatch(sent, nerr, t.wire.src, curDst, unix.IPPROTO_UDP, lastPLen)
		} else if nerr > 0 {
			noteWireTxErr(nerr)
		}
		for i := 0; i < batch.n; i++ {
			putBuf(batch.frames[i])
			batch.frames[i] = nil
		}
		batch.reset()
		haveDst = false
	}

	addPkt := func(routeDst [4]byte, payload []byte) {
		if haveDst && routeDst != curDst {
			flush()
		}
		curDst = routeDst
		haveDst = true
		frame := getBuf()
		out := buildWireUDP(frame, t.wire.src, routeDst, uint16(port), uint16(port), payload)
		batch.add(frame, len(out), routeDst, 0)
		lastPLen = len(payload)
		if batch.n >= bsz {
			flush()
		}
	}

	poller.Run(
		func() {
			statInc(statUDPTxPoll)
			if batch.n > 0 {
				flush()
			}
		},
		func(pkt []byte, n int) bool {
			statInc(statUDPTxRead)
			var routeDst [4]byte
			if t.cfg.Mode == "client" {
				routeDst = t.peerIP
			} else if v := t.lastRoute.Load(); v != nil {
				routeDst = v.([4]byte)
			} else {
				statInc(statUDPTxNoDst)
				if t.wire.on {
					wireMon.noteTxNoDst()
				}
				return true
			}
			addPkt(routeDst, pkt[:n])
			return !t.stop.stopped()
		},
	)
	flush()
}

func (t *UdpTunnel) rxLoop(conn *net.UDPConn, tun *os.File) {
	rawFd, err := udpConnFD(conn)
	if err != nil {
		t.rxLoopBlocking(conn, tun)
		return
	}
	_ = unix.SetNonblock(rawFd, true)

	var rb rxMmsgBatch
	rb.init(perfBatchSize())
	defer rb.release()

	peer, local := t.peerIP, t.localIP
	bsz := perfBatchSize()
	pollMs := perfPollMs()
	idleMs := pollMs
	batch := newTunRxBatch(bsz)
	// Track last stored peer to avoid a heap allocation on every received packet.
	var lastPeerAddr [4]byte
	var lastPeerPort uint16

	flush := func() {
		n, err := batch.flush(tun)
		if n == 0 {
			return
		}
		if err != nil {
			statInc(statUDPRxDropWrite)
			if !t.stop.stopped() {
				logDiagOnce("udp:tun_write", 15*time.Second,
					fmt.Sprintf("UDP TUN write failed: %v (%d pkt dropped)", err, n))
			}
		} else {
			statAdd(statUDPRxWrite, uint64(n))
		}
	}
	defer flush()

	for {
		got, err := rb.recv(rawFd)
		if got == 0 {
			if t.stop.stopped() {
				return
			}
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == nil {
				flush()
				_ = pollFD(rawFd, unix.POLLIN, idleMs)
				idleMs = idleBackoff(idleMs, pollMs)
				continue
			}
			if err == unix.EINTR {
				continue
			}
			continue
		}
		idleMs = pollMs
		for i := 0; i < got; i++ {
			pkt := rb.data(i)
			sa := rb.from4(i)
			if sa.Addr == local {
				statInc(statUDPRxDrop)
				continue
			}
			if t.cfg.Mode == "client" && sa.Addr != peer {
				statInc(statUDPRxDrop)
				continue
			}
			if t.cfg.Mode == "server" {
				// from4 already returns the port in host byte order.
				saPort := uint16(sa.Port)
				if sa.Addr != lastPeerAddr || saPort != lastPeerPort {
					lastPeerAddr = sa.Addr
					lastPeerPort = saPort
					t.lastPeer.Store(&net.UDPAddr{
						IP:   net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3]),
						Port: int(saPort),
					})
				}
			}
			statInc(statUDPRxRecv)
			NoteTunnelAlive()
			batch.add(pkt)
		}
		if batch.len() >= bsz {
			flush()
		}
	}
}

// rxLoopBlocking is the fallback when udpConnFD fails (single-packet reads).
func (t *UdpTunnel) rxLoopBlocking(conn *net.UDPConn, tun *os.File) {
	buf := getBuf()
	defer putBuf(buf)
	peer, local := t.peerIP, t.localIP
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if t.stop.stopped() {
				return
			}
			continue
		}
		ip4 := src.IP.To4()
		if ip4 == nil {
			continue
		}
		var sip [4]byte
		copy(sip[:], ip4)
		if sip == local {
			statInc(statUDPRxDrop)
			continue
		}
		if t.cfg.Mode == "client" && sip != peer {
			statInc(statUDPRxDrop)
			continue
		}
		if t.cfg.Mode == "server" {
			t.lastPeer.Store(src)
		}
		statInc(statUDPRxRecv)
		NoteTunnelAlive()
		if err := tunWrite(tun, buf[:n]); err != nil {
			statInc(statUDPRxDropWrite)
			if !t.stop.stopped() {
				logDiagOnce("udp:tun_write", 15*time.Second,
					fmt.Sprintf("UDP TUN write failed: %v", err))
			}
		} else {
			statInc(statUDPRxWrite)
		}
	}
}

// txPollLoop sends TUN packets to the UDP peer via sendmmsg batching.
//
// Uses RunOwned with hdrRoom=0: the poller's owned buffer IS the UDP payload,
// so batch.add receives it directly — no intermediate getBuf+copy per packet.
func (t *UdpTunnel) txPollLoop(conn *net.UDPConn) {
	rawFd, err := udpConnFD(conn)
	if err != nil {
		logDiagOnce("udp:tx_batch", 30*time.Second, "UDP sendmmsg unavailable: "+err.Error()+" (fallback path)")
		t.txPollLoopUnbatched(conn)
		return
	}

	poller := newTunPollerH(t.tun, &t.stop, 0)
	defer poller.close()

	var batch icmpTxBatch
	bsz := perfBatchSize()
	var curDst [4]byte
	var curPort uint16
	var haveDst bool

	flush := func() {
		if batch.n == 0 {
			return
		}
		statAdd(statUDPTxSend, uint64(batch.n))
		if nerr := mmsgSendBatch(rawFd, &batch); nerr > 0 {
			noteWireTxErr(nerr)
		}
		for i := 0; i < batch.n; i++ {
			putBuf(batch.frames[i])
			batch.frames[i] = nil
		}
		batch.reset()
		haveDst = false
	}

	poller.RunOwned(
		func() {
			statInc(statUDPTxPoll)
			if batch.n > 0 {
				flush()
			}
		},
		// buf is owned; payload is buf[0:n] (hdrRoom=0). Use buf directly — no copy.
		func(buf []byte, n int) bool {
			statInc(statUDPTxRead)
			var dst [4]byte
			var port uint16
			if t.cfg.Mode == "client" {
				dst = t.peerIP
				port = uint16(t.cfg.Transport.Port)
			} else if p, ok := t.lastPeer.Load().(*net.UDPAddr); ok && p != nil {
				copy(dst[:], p.IP.To4())
				port = uint16(p.Port)
			} else {
				statInc(statUDPTxNoDst)
				putBuf(buf)
				return !t.stop.stopped()
			}
			if haveDst && (dst != curDst || port != curPort) {
				flush()
			}
			curDst = dst
			curPort = port
			haveDst = true
			// buf IS the frame — owned, no extra allocation or copy.
			batch.add(buf, n, dst, port)
			if batch.n >= bsz {
				flush()
			}
			return !t.stop.stopped()
		},
	)
	flush()
}

func (t *UdpTunnel) txPollLoopUnbatched(conn *net.UDPConn) {
	poller := newTunPoller(t.tun, &t.stop)
	defer poller.close()

	poller.Run(
		func() { statInc(statUDPTxPoll) },
		func(pkt []byte, n int) bool {
			statInc(statUDPTxRead)
			var dst *net.UDPAddr
			if p, ok := t.lastPeer.Load().(*net.UDPAddr); ok && p != nil {
				dst = p
			}
			if dst == nil {
				statInc(statUDPTxNoDst)
				return true
			}
			if _, err := conn.WriteToUDP(pkt[:n], dst); err != nil && !t.stop.stopped() {
				logDebug("udp tx: " + err.Error())
			} else if err == nil {
				statInc(statUDPTxSend)
			}
			return !t.stop.stopped()
		},
	)
}

func (t *UdpTunnel) Down() error {
	t.doClean()
	logOK("udp tunnel torn down")
	return nil
}

func (t *UdpTunnel) doClean() {
	restoreTunnelTuning()
	t.stop.stop()
	if t.done != nil {
		close(t.done)
		t.done = nil
	}
	if t.udpConn != nil {
		t.udpConn.Close()
		t.udpConn = nil
	}
	if t.rawFd > 0 {
		unix.Close(t.rawFd)
		t.rawFd = 0
	}
	if t.tun != nil {
		t.tun.Close()
		t.tun = nil
	}
	releaseTunnelLock(t.lockFd)
	t.lockFd = nil
	delMSS(t.DevName())
	nlDown(t.DevName())
}

func (t *UdpTunnel) Status() {
	if l, err := netlink.LinkByName(t.DevName()); err == nil {
		fmt.Printf("  %s: flags=%v\n", l.Attrs().Name, l.Attrs().Flags)
	}
}
