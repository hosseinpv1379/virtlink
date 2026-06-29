// tun_udp.go — plain UDP tunnel.
//
// Performance: multi-queue TUN, sendmmsg TX batching, tuned socket buffers.
package udp

import (
	"virlink/internal/wire"
	"virlink/internal/platform"
	"virlink/internal/core"
	"virlink/internal/config"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync/atomic"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const udpRawSubnet = "10.20.42.0/24"

type UdpTunnel struct {
	cfg       *config.Config
	tun       *platform.TunDev
	udpConn   *net.UDPConn
	rawFd     int
	rawRxFd   int
	lockFd    *os.File
	done chan struct{}
	stop      platform.StoppedFlag
	lastPeer  atomic.Value
	lastRoute atomic.Value
	wire      wire.WireSpoof
	peerIP    [4]byte
	localIP   [4]byte
}

func (t *UdpTunnel) DevName() string   { return platform.TunnelDevName(t.cfg, "udp-tun0") }
func (t *UdpTunnel) OverlayIP() string { return core.OverlayAddr(t.cfg, udpRawSubnet) }
func (t *UdpTunnel) PeerIP() string    { return core.PeerAddr(t.cfg, udpRawSubnet) }

func (t *UdpTunnel) Up() error {
	c := t.cfg
	dev := t.DevName()
	addr := t.OverlayIP()
	peer := t.PeerIP()
	port := c.Transport.Port
	mtu := c.Tunnel.MTU
	if mtu == 0 {
		// 1440 like tcp: one outer UDP datagram fits common path MTU (1500).
		mtu = 1440
	}
	t.peerIP = platform.IpTo4(c.RemoteIP)
	t.localIP = platform.IpTo4(c.LocalIP)
	t.wire = wire.WireSpoofFrom(c)
	if c.Mode == "server" {
		t.lastRoute.Store(t.peerIP)
	}

	platform.Header("udp / " + c.Mode)
	platform.ApplyPerfFromConfig(c)
	platform.Step("perf: " + platform.PerfSummary())
	t.doClean()
	t.stop.Reset()

	var err error
	t.lockFd, err = platform.AcquireTunnelLock(dev)
	if err != nil {
		return err
	}

	t.tun, err = platform.OpenTunMulti(dev, platform.PerfTunQueues())
	if err != nil {
		return fmt.Errorf("tun: %w", err)
	}
	l, _ := netlink.LinkByName(dev)
	netlink.LinkSetMTU(l, mtu)
	a, _ := netlink.ParseAddr(addr)
	netlink.AddrAdd(l, a)
	netlink.LinkSetUp(l)
	platform.LogOK(fmt.Sprintf("%s  %s  queues=%d", dev, addr, t.tun.QueueCount()))

	platform.Step(fmt.Sprintf("tuning (%s)...", platform.TuningModeLabel(c)))
	platform.ApplyTunnelTuning(c, dev)

	if t.wire.On {
		t.rawFd, err = wire.OpenRawWire()
		if err != nil {
			return fmt.Errorf("SOCK_RAW udp tx: %w", err)
		}
		_ = unix.SetNonblock(t.rawFd, true)
		t.rawRxFd, err = wire.OpenRawWireRx()
		if err != nil {
			return fmt.Errorf("SOCK_RAW udp rx: %w", err)
		}
		_ = unix.SetNonblock(t.rawRxFd, true)
		platform.LogOK(fmt.Sprintf("raw UDP (IPPROTO_RAW) :%d", port))
		wire.LogWireSpoof(t.cfg, t.wire)
	} else {
		t.udpConn, err = net.ListenUDP("udp4", &net.UDPAddr{Port: port})
		if err != nil {
			return fmt.Errorf("udp :%d: %w", port, err)
		}
		platform.TuneUDPConn(t.udpConn)
		t.lastPeer.Store(&net.UDPAddr{IP: net.ParseIP(c.RemoteIP), Port: port})
		platform.LogOK(fmt.Sprintf("UDP :%d", port))
	}

	platform.AddMSS(c, dev)
	t.done = make(chan struct{})

	if t.wire.On {
		go t.rxLoopRaw(t.rawRxFd, t.tun.Fd0(), port)
		go t.txPollLoopRaw(t.rawFd, port)
	} else {
		conn := t.udpConn
		// Plain UDP: ReadFromUDP/WriteToUDP — reliable path (no recvmmsg/sendmmsg batch).
		go t.rxLoopBlocking(conn, t.tun.Fd0())
		go t.txPollLoopUnbatched(conn)
	}

	platform.Done(dev, addr, peer,
		fmt.Sprintf("transport : UDP :%d  poller×1", port),
		"test      : ping -c3 "+peer,
	)
	return nil
}

func (t *UdpTunnel) rxLoopRaw(rawFd int, tun *os.File, port int) {
	var rb platform.RxMmsgBatch
	rb.Init(platform.PerfBatchSize())
	defer rb.Release()

	peer := t.wire.WirePeer(t.peerIP)
	local := t.localIP
	pollMs := platform.PerfPollMs()
	idleMs := pollMs
	bsz := platform.PerfBatchSize()
	batch := platform.NewTunRxBatch(bsz)

	flush := func() {
		n, err := batch.Flush(tun)
		if n == 0 {
			return
		}
		if err != nil {
			platform.StatInc(platform.StatUDPRxDropWrite)
			if !t.stop.Stopped() {
				platform.LogWarn(fmt.Sprintf("udp tun write: %v (dropped %d pkt)", err, n))
			}
		} else {
			platform.StatAdd(platform.StatUDPRxWrite, uint64(n))
		}
	}
	defer flush()

	for {
		got, err := rb.Recv(rawFd)
		if got == 0 {
			if t.stop.Stopped() {
				return
			}
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == nil {
				flush()
				_ = platform.PollFD(rawFd, unix.POLLIN, idleMs)
				idleMs = platform.IdleBackoff(idleMs, pollMs)
				continue
			}
			if err == unix.EINTR {
				continue
			}
			platform.LogWarn("udp rx: " + err.Error())
			continue
		}
		idleMs = pollMs
		for i := 0; i < got; i++ {
			pkt := rb.Data(i)
			sa := rb.From4(i)
			if !wire.AcceptWirePeer(pkt, sa, local, peer, t.wire.Src(), t.wire, unix.IPPROTO_UDP) {
				platform.StatInc(platform.StatUDPRxDrop)
				continue
			}
			ihl, ok := wire.ParseIPv4Payload(pkt)
			if !ok {
				continue
			}
			n := len(pkt)
			if n < ihl+wire.UdpHdrLen {
				continue
			}
			if int(binary.BigEndian.Uint16(pkt[ihl+2:])) != port {
				platform.StatInc(platform.StatUDPRxDrop)
				if wire.WireMonitorActive() {
					sport := binary.BigEndian.Uint16(pkt[ihl:])
					var src [4]byte
					copy(src[:], pkt[12:16])
					platform.LogWarn(fmt.Sprintf("[wire] RX drop bad_udp_port sport=%d want=%d outer src=%s",
						sport, port, wire.Ip4Fmt(src)))
				}
				continue
			}
			payload := pkt[ihl+wire.UdpHdrLen : n]
			if t.cfg.Mode == "server" {
				t.lastRoute.Store(wire.RememberPeerRoute(t.wire, sa.Addr, t.peerIP))
			}
			platform.StatInc(platform.StatUDPRxRecv)
			batch.Add(payload)
		}
		if batch.Len() >= bsz {
			flush()
		}
	}
}

func (t *UdpTunnel) txPollLoopRaw(rawFd int, port int) {
	poller := platform.NewTunPoller(t.tun, &t.stop)
	defer poller.Close()

	var batch platform.IcmpTxBatch
	bsz := platform.PerfBatchSize()
	var curDst [4]byte
	var haveDst bool
	var lastPLen int

	flush := func() {
		if batch.N() == 0 {
			return
		}
		platform.StatAdd(platform.StatUDPTxSend, uint64(batch.N()))
		nerr := platform.MmsgSendBatch(rawFd, &batch)
		if t.wire.On {
			sent := batch.N() - nerr
			if sent < 0 {
				sent = 0
			}
			// WireMon.noteTxBatch(sent, nerr, t.wire.Src(), curDst, unix.IPPROTO_UDP, _ = lastPLen)
		} else if nerr > 0 {
			wire.NoteWireTxErr(nerr)
		}
		for i := 0; i < batch.N(); i++ {
			platform.PutBuf(batch.Frame(i))
			batch.SetFrame(i, nil)
		}
		batch.Reset()
		haveDst = false
	}

	addPkt := func(routeDst [4]byte, payload []byte) {
		if haveDst && routeDst != curDst {
			flush()
		}
		curDst = routeDst
		haveDst = true
		frame := platform.GetBuf()
		out := wire.BuildWireUDP(frame, t.wire.Src(), routeDst, uint16(port), uint16(port), payload)
		batch.Add(frame, len(out), routeDst, 0)
		lastPLen = len(payload)
		_ = lastPLen
		if batch.N() >= bsz {
			flush()
		}
	}

	poller.Run(
		func() {
			platform.StatInc(platform.StatUDPTxPoll)
			if batch.N() > 0 {
				flush()
			}
		},
		func(pkt []byte, n int) bool {
			platform.StatInc(platform.StatUDPTxRead)
			var routeDst [4]byte
			if t.cfg.Mode == "client" {
				routeDst = t.peerIP
			} else if v := t.lastRoute.Load(); v != nil {
				routeDst = v.([4]byte)
			} else {
				platform.StatInc(platform.StatUDPTxNoDst)
				if t.wire.On {
					// WireMon.noteTxNoDst()
				}
				return true
			}
			addPkt(routeDst, pkt[:n])
			return !t.stop.Stopped()
		},
	)
	flush()
}

func (t *UdpTunnel) rxLoop(conn *net.UDPConn, tun *os.File) {
	rawFd, err := platform.UdpConnFD(conn)
	if err != nil {
		t.rxLoopBlocking(conn, tun)
		return
	}
	_ = unix.SetNonblock(rawFd, true)

	var rb platform.RxMmsgBatch
	rb.Init(platform.PerfBatchSize())
	defer rb.Release()

	peer, local := t.peerIP, t.localIP
	bsz := platform.PerfBatchSize()
	pollMs := platform.PerfPollMs()
	idleMs := pollMs
	batch := platform.NewTunRxBatch(bsz)
	// Track last stored peer to avoid a heap allocation on every received packet.
	var lastPeerAddr [4]byte
	var lastPeerPort uint16

	flush := func() {
		n, err := batch.Flush(tun)
		if n == 0 {
			return
		}
		if err != nil {
			platform.StatInc(platform.StatUDPRxDropWrite)
			if !t.stop.Stopped() {
				platform.LogWarn(fmt.Sprintf("udp tun write: %v (dropped %d pkt)", err, n))
			}
		} else {
			platform.StatAdd(platform.StatUDPRxWrite, uint64(n))
		}
	}
	defer flush()

	for {
		got, err := rb.Recv(rawFd)
		if got == 0 {
			if t.stop.Stopped() {
				return
			}
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == nil {
				flush()
				_ = platform.PollFD(rawFd, unix.POLLIN, idleMs)
				idleMs = platform.IdleBackoff(idleMs, pollMs)
				continue
			}
			if err == unix.EINTR {
				continue
			}
			continue
		}
		idleMs = pollMs
		for i := 0; i < got; i++ {
			pkt := rb.Data(i)
			sa := rb.From4(i)
			if sa.Addr == local {
				platform.StatInc(platform.StatUDPRxDrop)
				continue
			}
			if t.cfg.Mode == "client" && sa.Addr != peer {
				platform.StatInc(platform.StatUDPRxDrop)
				continue
			}
			if t.cfg.Mode == "server" {
				// From4() already converts RawSockaddrInet4.Port to host order.
				saPort := uint16(sa.Port)
				if sa.Addr != lastPeerAddr || saPort != lastPeerPort {
					lastPeerAddr = sa.Addr
					lastPeerPort = saPort
					t.lastPeer.Store(&net.UDPAddr{
						IP:   net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3]),
						Port: sa.Port,
					})
				}
			}
			platform.StatInc(platform.StatUDPRxRecv)
			batch.Add(pkt)
		}
		if batch.Len() >= bsz {
			flush()
		}
	}
}

// rxLoopBlocking is the fallback when platform.UdpConnFD fails (single-packet reads).
func (t *UdpTunnel) rxLoopBlocking(conn *net.UDPConn, tun *os.File) {
	buf := platform.GetBuf()
	defer platform.PutBuf(buf)
	peer, local := t.peerIP, t.localIP
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if t.stop.Stopped() {
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
			platform.StatInc(platform.StatUDPRxDrop)
			continue
		}
		if t.cfg.Mode == "client" && sip != peer {
			platform.StatInc(platform.StatUDPRxDrop)
			continue
		}
		if t.cfg.Mode == "server" {
			t.lastPeer.Store(src)
		}
		platform.StatInc(platform.StatUDPRxRecv)
		batch := platform.NewTunRxBatch(1)
		batch.Add(buf[:n])
		if _, err := batch.Flush(tun); err != nil {
			platform.StatInc(platform.StatUDPRxDropWrite)
			if !t.stop.Stopped() {
				platform.LogWarn(fmt.Sprintf("udp tun write: %v", err))
			}
		} else {
			platform.StatInc(platform.StatUDPRxWrite)
		}
	}
}

// txPollLoop sends TUN packets to the UDP peer via sendmmsg batching.
//
// Uses RunOwned with hdrRoom=0: the poller's owned buffer IS the UDP payload,
// so batch.add receives it directly — no intermediate platform.GetBuf+copy per packet.
func (t *UdpTunnel) txPollLoop(conn *net.UDPConn) {
	poller := platform.NewTunPollerH(t.tun, &t.stop, 0)
	defer poller.Close()

	var batch platform.IcmpTxBatch
	bsz := platform.PerfBatchSize()
	var curDst [4]byte
	var curPort uint16
	var haveDst bool

	flush := func() {
		if batch.N() == 0 {
			return
		}
		dst := &net.UDPAddr{
			IP:   net.IPv4(curDst[0], curDst[1], curDst[2], curDst[3]),
			Port: int(curPort),
		}
		var sent uint64
		for i := 0; i < batch.N(); i++ {
			plen := batch.PktLen(i)
			if _, err := conn.WriteToUDP(batch.Frame(i)[:plen], dst); err != nil {
				if !t.stop.Stopped() {
					platform.LogDebug("udp tx: " + err.Error())
				}
			} else {
				sent++
			}
			platform.PutBuf(batch.Frame(i))
			batch.SetFrame(i, nil)
		}
		if sent > 0 {
			platform.StatAdd(platform.StatUDPTxSend, sent)
		}
		batch.Reset()
		haveDst = false
	}

	poller.RunOwned(
		func() {
			platform.StatInc(platform.StatUDPTxPoll)
			if batch.N() > 0 {
				flush()
			}
		},
		// buf is owned; payload is buf[0:n] (hdrRoom=0). Use buf directly — no copy.
		func(buf []byte, n int) bool {
			platform.StatInc(platform.StatUDPTxRead)
			var dst [4]byte
			var port uint16
			if t.cfg.Mode == "client" {
				dst = t.peerIP
				port = uint16(t.cfg.Transport.Port)
			} else if p, ok := t.lastPeer.Load().(*net.UDPAddr); ok && p != nil {
				copy(dst[:], p.IP.To4())
				port = uint16(p.Port)
			} else {
				platform.StatInc(platform.StatUDPTxNoDst)
				platform.PutBuf(buf)
				return !t.stop.Stopped()
			}
			if haveDst && (dst != curDst || port != curPort) {
				flush()
			}
			curDst = dst
			curPort = port
			haveDst = true
			// buf IS the frame — owned, no extra allocation or copy.
			batch.Add(buf, n, dst, port)
			if batch.N() >= bsz {
				flush()
			}
			return !t.stop.Stopped()
		},
	)
	flush()
}

func (t *UdpTunnel) wireDst() *net.UDPAddr {
	if p, ok := t.lastPeer.Load().(*net.UDPAddr); ok && p != nil {
		return p
	}
	if t.cfg.Mode == "client" {
		return &net.UDPAddr{
			IP:   net.IPv4(t.peerIP[0], t.peerIP[1], t.peerIP[2], t.peerIP[3]),
			Port: t.cfg.Transport.Port,
		}
	}
	return nil
}

func (t *UdpTunnel) txPollLoopUnbatched(conn *net.UDPConn) {
	poller := platform.NewTunPollerH(t.tun, &t.stop, 0)
	defer poller.Close()

	poller.RunOwned(
		func() { platform.StatInc(platform.StatUDPTxPoll) },
		func(buf []byte, n int) bool {
			platform.StatInc(platform.StatUDPTxRead)
			dst := t.wireDst()
			if dst == nil {
				platform.StatInc(platform.StatUDPTxNoDst)
				platform.PutBuf(buf)
				return !t.stop.Stopped()
			}
			if _, err := conn.WriteToUDP(buf[:n], dst); err != nil && !t.stop.Stopped() {
				platform.LogDebug("udp tx: " + err.Error())
			} else if err == nil {
				platform.StatInc(platform.StatUDPTxSend)
			}
			platform.PutBuf(buf)
			return !t.stop.Stopped()
		},
	)
}

func (t *UdpTunnel) Down() error {
	t.doClean()
	platform.LogOK("udp tunnel torn down")
	return nil
}

func (t *UdpTunnel) doClean() {
	platform.RestoreTunnelTuning()
	t.stop.Stop()
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
	if t.rawRxFd > 0 {
		unix.Close(t.rawRxFd)
		t.rawRxFd = 0
	}
	if t.tun != nil {
		t.tun.Close()
		t.tun = nil
	}
	platform.ReleaseTunnelLock(t.lockFd)
	t.lockFd = nil
	platform.DelMSS(t.DevName())
	platform.NlDown(t.DevName())
}

func (t *UdpTunnel) Status() {
	if l, err := netlink.LinkByName(t.DevName()); err == nil {
		fmt.Printf("  %s: flags=%v\n", l.Attrs().Name, l.Attrs().Flags)
	}
}
