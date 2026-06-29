// tun_icmp.go — ICMP Echo tunnel (IP protocol 1).
//
// Performance (v2.8.1):
//   • Single TX poller for all TUN queues (1 goroutine vs N)
//   • sendmmsg batching, inner-IP dedup only when queues > 1
//   • Per-protocol userspace defaults via platform.ApplyPerfFromConfig
package icmp

import (
	"virlink/internal/wire"
	"virlink/internal/platform"
	"virlink/internal/core"
	"virlink/internal/config"
	"encoding/binary"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	icmpSubnet    = "10.20.43.0/24"
	icmpTunID     = uint16(0xCAFE)
	icmpEchoReq   = 8
	icmpHdrRoom   = 8 // RunOwned payload offset; buf[0:2] holds len for stream writers
	icmpTxChanCap = 32
)

type IcmpTunnel struct {
	cfg      *config.Config
	tun      *platform.TunDev
	rawFd    int
	rawTxFds []int
	lockFd   *os.File
	done chan struct{}
	stop    platform.StoppedFlag
	seq     atomic.Uint32
	dedup   platform.AtomicSeqDedup
	txDedup platform.IpPktDedup
	wire    wire.WireSpoof
	lastSrc atomic.Value
	peerIP  [4]byte
	localIP [4]byte
}

func (t *IcmpTunnel) DevName() string   { return platform.TunnelDevName(t.cfg, "icmp-tun0") }
func (t *IcmpTunnel) OverlayIP() string { return core.OverlayAddr(t.cfg, icmpSubnet) }
func (t *IcmpTunnel) PeerIP() string    { return core.PeerAddr(t.cfg, icmpSubnet) }

func (t *IcmpTunnel) Up() error {
	c := t.cfg
	dev := t.DevName()
	addr := t.OverlayIP()
	peer := t.PeerIP()
	mtu := c.Tunnel.MTU
	if mtu == 0 {
		mtu = 1472
	}
	t.peerIP = platform.IpTo4(c.RemoteIP)
	t.localIP = platform.IpTo4(c.LocalIP)
	t.wire = wire.WireSpoofFrom(c)
	if c.Mode == "server" {
		t.lastSrc.Store(t.peerIP)
	}

	platform.Header("icmp / " + c.Mode)
	platform.ApplyPerfFromConfig(c)
	platform.Step("perf: " + platform.PerfSummary())

	platform.Step("cleanup...")
	t.doClean()
	t.stop.Reset()
	t.dedup.Reset()
	t.txDedup.Reset()

	platform.Step("instance lock...")
	var err error
	t.lockFd, err = platform.AcquireTunnelLock(dev)
	if err != nil {
		return err
	}

	platform.Step(fmt.Sprintf("TUN device %s ×%d queues...", dev, platform.PerfTunQueues()))
	t.tun, err = platform.OpenTunMulti(dev, platform.PerfTunQueues())
	if err != nil {
		return fmt.Errorf("tun: %w", err)
	}
	l, err := netlink.LinkByName(dev)
	if err != nil {
		return fmt.Errorf("link %s: %w", dev, err)
	}
	netlink.LinkSetMTU(l, mtu)
	a, _ := netlink.ParseAddr(addr)
	netlink.AddrAdd(l, a)
	netlink.LinkSetUp(l)
	platform.LogOK(fmt.Sprintf("%s  %s  MTU=%d  queues=%d", dev, addr, mtu, t.tun.QueueCount()))

	platform.Step(fmt.Sprintf("tuning (%s)...", platform.TuningModeLabel(c)))
	platform.ApplyTunnelTuning(c, dev)

	platform.Step("raw ICMP socket...")
	if err := t.openRawSockets(); err != nil {
		return err
	}
	platform.LogOK("raw ICMP socket ready")
	wire.LogWireSpoof(t.cfg, t.wire)

	platform.AddMSS(c, dev)
	t.done = make(chan struct{})

	go t.rxLoop(t.rawFd, t.tun.Fd0())
	if len(t.rawTxFds) > 1 {
		go t.txPollLoopMulti(t.rawTxFds)
	} else {
		go t.txPollLoop(t.rawFd)
	}

	streams := len(t.rawTxFds)
	if streams <= 1 {
		streams = 1
	}
	platform.Done(dev, addr, peer,
		fmt.Sprintf("transport : ICMP ×%d streams  poller×1  queues=%d  batch=%d",
			streams, t.tun.QueueCount(), platform.PerfBatchSize()),
		"filter   : peer="+c.RemoteIP,
		"test     : ping -c3 "+peer,
	)
	return nil
}

func (t *IcmpTunnel) openRawSockets() error {
	streams := platform.PerfTcpStreams()
	if t.wire.On || streams <= 1 {
		fd, err := t.openOneRaw()
		if err != nil {
			return err
		}
		t.rawFd = fd
		return nil
	}

	fds := make([]int, streams)
	for i := 0; i < streams; i++ {
		fd, err := t.openOneRaw()
		if err != nil {
			platform.CloseFDs(fds[:i])
			return fmt.Errorf("SOCK_RAW stream %d: %w", i, err)
		}
		fds[i] = fd
	}
	t.rawFd = fds[0]
	t.rawTxFds = fds
	platform.LogOK(fmt.Sprintf("raw ICMP ×%d TX streams (RX on stream 0)", streams))
	return nil
}

func (t *IcmpTunnel) openOneRaw() (int, error) {
	var fd int
	var err error
	if t.wire.On {
		fd, err = wire.OpenRawWire()
	} else {
		fd, err = platform.OpenRawICMP()
	}
	if err != nil {
		return 0, err
	}
	platform.TuneRawSock(fd)
	if !t.wire.On {
		_ = platform.InstallICMPFilter(fd)
	}
	_ = unix.SetNonblock(fd, true)
	return fd, nil
}

func icmpStreamSlot(data []byte, streams int) int {
	if streams <= 1 {
		return 0
	}
	return int(platform.HashIPPacket(data) % uint32(streams))
}

func (t *IcmpTunnel) resolveDst() ([4]byte, bool) {
	if t.cfg.Mode == "client" {
		return t.peerIP, true
	}
	if v := t.lastSrc.Load(); v != nil {
		return v.([4]byte), true
	}
	return [4]byte{}, false
}

// txPollLoop — single raw fd; RunOwned avoids GetICMPFrame alloc on plain ICMP.
func (t *IcmpTunnel) txPollLoop(rawFd int) {
	if t.wire.On {
		t.txPollLoopWire(rawFd)
		return
	}

	poller := platform.NewTunPollerH(t.tun, &t.stop, icmpHdrRoom)
	defer poller.Close()

	var batch platform.IcmpTxBatch
	bsz := platform.PerfBatchSize()
	useDedup := t.tun.QueueCount() > 1

	flush := func() {
		if batch.N() == 0 {
			return
		}
		platform.StatAdd(platform.StatICMPTxSend, uint64(batch.N()))
		if nerr := platform.IcmpSendBatch(rawFd, &batch); nerr > 0 {
			wire.NoteWireTxErr(nerr)
		}
		for i := 0; i < batch.N(); i++ {
			platform.PutBuf(batch.Frame(i))
			batch.SetFrame(i, nil)
		}
		batch.Reset()
	}

	poller.RunOwned(
		func() {
			platform.StatInc(platform.StatICMPTxPoll)
			if batch.N() > 0 {
				flush()
			}
		},
		func(buf []byte, n int) bool {
			platform.StatInc(platform.StatICMPTxRead)
			dst, ok := t.resolveDst()
			if !ok {
				platform.StatInc(platform.StatICMPTxNoDst)
				platform.PutBuf(buf)
				return !t.stop.Stopped()
			}
			payload := buf[icmpHdrRoom : icmpHdrRoom+n]
			if useDedup && t.txDedup.Dup(payload) {
				platform.StatInc(platform.StatICMPTxDedup)
				platform.PutBuf(buf)
				return !t.stop.Stopped()
			}
			seq := uint16(t.seq.Add(1))
			built := platform.BuildICMPFrame(buf, icmpTunID, seq, payload)
			batch.Add(buf, len(built), dst, 0)
			if batch.N() >= bsz {
				flush()
			}
			return !t.stop.Stopped()
		},
	)
	flush()
}

func (t *IcmpTunnel) txPollLoopMulti(rawFds []int) {
	streams := len(rawFds)
	chs := make([]chan []byte, streams)
	for i := range chs {
		chs[i] = make(chan []byte, icmpTxChanCap)
		go t.icmpStreamWriter(rawFds[i], chs[i])
	}

	poller := platform.NewTunPollerH(t.tun, &t.stop, icmpHdrRoom)
	defer func() {
		poller.Close()
		for _, ch := range chs {
			close(ch)
		}
	}()

	useDedup := t.tun.QueueCount() > 1

	poller.RunOwned(
		nil,
		func(buf []byte, n int) bool {
			platform.StatInc(platform.StatICMPTxRead)
			payload := buf[icmpHdrRoom : icmpHdrRoom+n]
			if useDedup && t.txDedup.Dup(payload) {
				platform.StatInc(platform.StatICMPTxDedup)
				platform.PutBuf(buf)
				return !t.stop.Stopped()
			}
			binary.BigEndian.PutUint16(buf[:2], uint16(n))
			slot := icmpStreamSlot(payload, streams)
			for i := 0; i < streams; i++ {
				idx := (slot + i) % streams
				select {
				case chs[idx] <- buf:
					return !t.stop.Stopped()
				default:
				}
			}
			chs[slot] <- buf
			return !t.stop.Stopped()
		},
	)
}

func (t *IcmpTunnel) icmpStreamWriter(rawFd int, ch <-chan []byte) {
	bsz := platform.PerfBatchSize()
	var batch platform.IcmpTxBatch
	pollMs := time.Duration(platform.PerfPollMs()) * time.Millisecond

	flush := func() {
		if batch.N() == 0 {
			return
		}
		platform.StatAdd(platform.StatICMPTxSend, uint64(batch.N()))
		if nerr := platform.IcmpSendBatch(rawFd, &batch); nerr > 0 {
			wire.NoteWireTxErr(nerr)
		}
		for i := 0; i < batch.N(); i++ {
			platform.PutBuf(batch.Frame(i))
			batch.SetFrame(i, nil)
		}
		batch.Reset()
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
			dst, ok := t.resolveDst()
			if !ok {
				platform.StatInc(platform.StatICMPTxNoDst)
				platform.PutBuf(buf)
				continue
			}
			seq := uint16(t.seq.Add(1))
			payload := buf[icmpHdrRoom : icmpHdrRoom+n]
			built := platform.BuildICMPFrame(buf, icmpTunID, seq, payload)
			batch.Add(buf, len(built), dst, 0)
			if batch.N() >= bsz {
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

// txPollLoopWire — wire/mangle path keeps separate frame pool (IPv4 header room).
func (t *IcmpTunnel) txPollLoopWire(rawFd int) {
	poller := platform.NewTunPoller(t.tun, &t.stop)
	defer poller.Close()

	var batch platform.IcmpTxBatch
	bsz := platform.PerfBatchSize()
	useDedup := t.tun.QueueCount() > 1
	var lastDst [4]byte
	var lastPLen int

	flush := func() {
		if batch.N() == 0 {
			return
		}
		platform.StatAdd(platform.StatICMPTxSend, uint64(batch.N()))
		nerr := platform.IcmpSendBatch(rawFd, &batch)
		if t.wire.On {
			sent := batch.N() - nerr
			if sent < 0 {
				sent = 0
			}
			// WireMon.noteTxBatch(sent, nerr, t.wire.Src(), lastDst, unix.IPPROTO_ICMP, _ = lastPLen)
		} else if nerr > 0 {
			wire.NoteWireTxErr(nerr)
		}
		for i := 0; i < batch.N(); i++ {
			platform.PutICMPFrame(batch.Frame(i))
			batch.SetFrame(i, nil)
		}
		batch.Reset()
	}

	poller.Run(
		func() {
			platform.StatInc(platform.StatICMPTxPoll)
			if batch.N() > 0 {
				flush()
			}
		},
		func(pkt []byte, n int) bool {
			platform.StatInc(platform.StatICMPTxRead)
			dst, ok := t.resolveDst()
			if !ok {
				platform.StatInc(platform.StatICMPTxNoDst)
				if t.wire.On {
					// WireMon.noteTxNoDst()
				}
				return true
			}
			payload := pkt[:n]
			if useDedup && t.txDedup.Dup(payload) {
				platform.StatInc(platform.StatICMPTxDedup)
				return true
			}
			frame := platform.GetICMPFrame()
			seq := uint16(t.seq.Add(1))
			var built []byte
			if t.wire.On {
				built = wire.BuildWireICMP(frame, t.wire.Src(), dst, icmpTunID, seq, payload)
			} else {
				built = platform.BuildICMPFrame(frame, icmpTunID, seq, payload)
			}
			batch.Add(frame, len(built), dst, 0)
			lastDst = dst
			lastPLen = len(payload)
			_, _ = lastDst, lastPLen
			if batch.N() >= bsz {
				flush()
			}
			return !t.stop.Stopped()
		},
	)
	flush()
}

func (t *IcmpTunnel) rxLoop(rawFd int, tun *os.File) {
	var rb platform.RxMmsgBatch
	rb.Init(platform.PerfBatchSize())
	defer rb.Release()

	peer := t.wire.WirePeer(t.peerIP)
	local := t.localIP
	bsz := platform.PerfBatchSize()
	pollMs := platform.PerfPollMs()
	idleMs := pollMs
	batch := platform.NewTunRxBatch(bsz)

	flush := func() {
		n, err := batch.Flush(tun)
		if n == 0 {
			return
		}
		if err != nil {
			platform.StatInc(platform.StatICMPRxDropWrite)
			if !t.stop.Stopped() {
				platform.LogWarn(fmt.Sprintf("icmp tun write: %v (dropped %d pkt)", err, n))
			}
		} else {
			platform.StatAdd(platform.StatICMPRxWrite, uint64(n))
		}
	}
	defer flush()

	for !t.stop.Stopped() {
		got, err := rb.Recv(rawFd)
		if got == 0 {
			if t.stop.Stopped() {
				return
			}
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == nil {
				flush()
				platform.StatInc(platform.StatICMPRxPoll)
				_ = platform.PollFD(rawFd, unix.POLLIN, idleMs)
				idleMs = platform.IdleBackoff(idleMs, pollMs)
				continue
			}
			if err == unix.EINTR {
				continue
			}
			platform.LogWarn("icmp rx: " + err.Error())
			continue
		}
		idleMs = pollMs
		for i := 0; i < got; i++ {
			pkt := platform.TrimIPv4Packet(rb.Data(i))
			sa := rb.From4(i)
			// Kernel echo replies (type 0) to our wire pings — not tunnel traffic.
			if platform.IcmpWireCarrierType(pkt, t.wire.On) != icmpEchoReq {
				continue
			}
			if !wire.AcceptWirePeer(pkt, sa, local, peer, t.wire.Src(), t.wire, unix.IPPROTO_ICMP) {
				platform.StatInc(platform.StatICMPRxDropPeer)
				continue
			}
			icmp, ok := platform.ParseIcmpWirePacket(pkt, t.wire.On)
			if !ok {
				continue
			}
			if icmp[0] != icmpEchoReq || binary.BigEndian.Uint16(icmp[4:6]) != icmpTunID {
				platform.StatInc(platform.StatICMPRxDropProto)
				continue
			}
			platform.StatInc(platform.StatICMPRxRecv)
			seq := binary.BigEndian.Uint16(icmp[6:8])
			if t.dedup.Dup(seq) {
				platform.StatInc(platform.StatICMPRxDropSeq)
				continue
			}
			inner := icmp[8:]
			if t.cfg.Mode == "server" {
				t.lastSrc.Store(wire.RememberPeerRoute(t.wire, sa.Addr, t.peerIP))
			}
			batch.Add(inner)
		}
		if batch.Len() >= bsz {
			flush()
		}
	}
}

func (t *IcmpTunnel) Down() error {
	t.doClean()
	platform.LogOK("icmp tunnel torn down")
	return nil
}

func (t *IcmpTunnel) doClean() {
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
	if len(t.rawTxFds) > 0 {
		platform.CloseFDs(t.rawTxFds)
		t.rawTxFds = nil
		t.rawFd = 0
	} else if t.rawFd > 0 {
		unix.Close(t.rawFd)
		t.rawFd = 0
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

func (t *IcmpTunnel) Status() {
	if l, err := netlink.LinkByName(t.DevName()); err == nil {
		fmt.Printf("  %s: flags=%v\n", l.Attrs().Name, l.Attrs().Flags)
	}
}
