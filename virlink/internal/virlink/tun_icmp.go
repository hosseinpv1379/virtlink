// tun_icmp.go — ICMP Echo tunnel (IP protocol 1).
//
// Performance (v2.8.1):
//   • Single TX poller for all TUN queues (1 goroutine vs N)
//   • sendmmsg batching, inner-IP dedup only when queues > 1
//   • Per-protocol userspace defaults via applyPerfFromConfig
package virlink

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	icmpSubnet  = "10.20.43.0/24"
	icmpTunID   = uint16(0xCAFE)
	icmpEchoReq = 8
)

type IcmpTunnel struct {
	cfg     *Config
	tun     *TunDev
	rawFd   int
	lockFd  *os.File
	done    chan struct{}
	stop    stoppedFlag
	seq     atomic.Uint32
	dedup   atomicSeqDedup
	txDedup ipPktDedup
	wire    wireSpoof
	lastSrc atomic.Value
	peerIP  [4]byte
	localIP [4]byte
}

func (t *IcmpTunnel) DevName() string   { return tunnelDevName(t.cfg, "icmp-tun0") }
func (t *IcmpTunnel) OverlayIP() string { return overlayAddr(t.cfg, icmpSubnet) }
func (t *IcmpTunnel) PeerIP() string    { return peerAddr(t.cfg, icmpSubnet) }

func (t *IcmpTunnel) Up() error {
	c := t.cfg
	dev := t.DevName()
	addr := t.OverlayIP()
	peer := t.PeerIP()
	mtu := c.Tunnel.MTU
	if mtu == 0 {
		mtu = 1472
	}
	t.peerIP = ipTo4(c.RemoteIP)
	t.localIP = ipTo4(c.LocalIP)
	t.wire = wireSpoofFrom(c)
	if c.Mode == "server" {
		t.lastSrc.Store(t.peerIP)
	}

	header("icmp / " + c.Mode)
	applyPerfFromConfig(c)
	step("perf: " + perfSummary())

	step("cleanup...")
	t.doClean()
	t.stop.reset()
	t.dedup.reset()
	t.txDedup.reset()

	step("instance lock...")
	var err error
	t.lockFd, err = acquireTunnelLock(dev)
	if err != nil {
		return err
	}

	step(fmt.Sprintf("TUN device %s ×%d queues...", dev, perfTunQueues()))
	t.tun, err = openTunMulti(dev, perfTunQueues())
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
	logOK(fmt.Sprintf("%s  %s  MTU=%d  queues=%d", dev, addr, mtu, t.tun.QueueCount()))

	step(fmt.Sprintf("tuning (%s)...", tuningModeLabel(c)))
	applyTunnelTuning(c, dev)

	step("raw ICMP socket...")
	if t.wire.on {
		t.rawFd, err = openRawWire()
	} else {
		t.rawFd, err = openRawICMP()
	}
	if err != nil {
		return fmt.Errorf("SOCK_RAW: %w", err)
	}
	tuneRawSock(t.rawFd)
	if !t.wire.on {
		_ = installICMPFilter(t.rawFd)
	}
	_ = unix.SetNonblock(t.rawFd, true)
	logOK("raw ICMP socket ready")
	logWireSpoof(t.cfg, t.wire)

	addMSS(c, dev)
	t.done = make(chan struct{})

	rawFd := t.rawFd
	go t.rxLoop(rawFd, t.tun.Fd0())
	go t.txPollLoop(rawFd)

	done(dev, addr, peer,
		fmt.Sprintf("transport : ICMP poller×1  queues=%d  batch=%d", t.tun.QueueCount(), perfBatchSize()),
		"filter   : peer="+c.RemoteIP,
		"test     : ping -c3 "+peer,
	)
	return nil
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

// txPollLoop — single goroutine polls all TUN queues, batches ICMP sends.
func (t *IcmpTunnel) txPollLoop(rawFd int) {
	poller := newTunPoller(t.tun, &t.stop)
	defer poller.close()

	var batch icmpTxBatch
	bsz := perfBatchSize()
	useDedup := t.tun.QueueCount() > 1
	var lastDst [4]byte
	var lastPLen int

	flush := func() {
		if batch.n == 0 {
			return
		}
		statAdd(statICMPTxSend, uint64(batch.n))
		nerr := icmpSendBatch(rawFd, &batch)
		if t.wire.on {
			sent := batch.n - nerr
			if sent < 0 {
				sent = 0
			}
			wireMon.noteTxBatch(sent, nerr, t.wire.src, lastDst, unix.IPPROTO_ICMP, lastPLen)
		} else if nerr > 0 {
			noteWireTxErr(nerr)
		}
		for i := 0; i < batch.n; i++ {
			putICMPFrame(batch.frames[i])
			batch.frames[i] = nil
		}
		batch.reset()
	}

	poller.Run(
		func() {
			statInc(statICMPTxPoll)
			if batch.n > 0 {
				flush()
			}
		},
		func(pkt []byte, n int) bool {
			statInc(statICMPTxRead)
			dst, ok := t.resolveDst()
			if !ok {
				statInc(statICMPTxNoDst)
				if t.wire.on {
					wireMon.noteTxNoDst()
				}
				return true
			}
			payload := pkt[:n]
			if useDedup && t.txDedup.dup(payload) {
				statInc(statICMPTxDedup)
				return true
			}
			frame := getICMPFrame()
			seq := uint16(t.seq.Add(1))
			var built []byte
			if t.wire.on {
				built = buildWireICMP(frame, t.wire.src, dst, icmpTunID, seq, payload)
			} else {
				built = buildICMPFrame(frame, icmpTunID, seq, payload)
			}
			batch.add(frame, len(built), dst, 0)
			lastDst = dst
			lastPLen = len(payload)
			if batch.n >= bsz {
				flush()
			}
			return !t.stop.stopped()
		},
	)
	flush()
}

func (t *IcmpTunnel) rxLoop(rawFd int, tun *os.File) {
	var rb rxMmsgBatch
	rb.init(perfBatchSize())
	defer rb.release()

	peer := t.wire.wirePeer(t.peerIP)
	local := t.localIP
	bsz := perfBatchSize()
	pollMs := perfPollMs()
	idleMs := pollMs
	batch := newTunRxBatch(bsz)

	flush := func() {
		n, err := batch.flush(tun)
		if n == 0 {
			return
		}
		if err != nil {
			statInc(statICMPRxDropWrite)
			if !t.stop.stopped() {
				logWarn(fmt.Sprintf("icmp tun write: %v (dropped %d pkt)", err, n))
			}
		} else {
			statAdd(statICMPRxWrite, uint64(n))
		}
	}
	defer flush()

	for !t.stop.stopped() {
		got, err := rb.recv(rawFd)
		if got == 0 {
			if t.stop.stopped() {
				return
			}
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == nil {
				flush()
				statInc(statICMPRxPoll)
				_ = pollFD(rawFd, unix.POLLIN, idleMs)
				idleMs = idleBackoff(idleMs, pollMs)
				continue
			}
			if err == unix.EINTR {
				continue
			}
			logWarn("icmp rx: " + err.Error())
			continue
		}
		idleMs = pollMs
		for i := 0; i < got; i++ {
			pkt := trimIPv4Packet(rb.data(i))
			sa := rb.from4(i)
			// Kernel echo replies (type 0) to our wire pings — not tunnel traffic.
			if icmpWireCarrierType(pkt, t.wire.on) != icmpEchoReq {
				continue
			}
			if !acceptWirePeer(pkt, sa, local, peer, t.wire.src, t.wire, unix.IPPROTO_ICMP) {
				statInc(statICMPRxDropPeer)
				continue
			}
			icmp, ok := parseIcmpWirePacket(pkt, t.wire.on)
			if !ok {
				continue
			}
			if icmp[0] != icmpEchoReq || binary.BigEndian.Uint16(icmp[4:6]) != icmpTunID {
				statInc(statICMPRxDropProto)
				continue
			}
			statInc(statICMPRxRecv)
			seq := binary.BigEndian.Uint16(icmp[6:8])
			if t.dedup.dup(seq) {
				statInc(statICMPRxDropSeq)
				continue
			}
			inner := icmp[8:]
			if t.cfg.Mode == "server" {
				t.lastSrc.Store(rememberPeerRoute(t.wire, sa.Addr, t.peerIP))
			}
			batch.add(inner)
		}
		if batch.len() >= bsz {
			flush()
		}
	}
}

func (t *IcmpTunnel) Down() error {
	t.doClean()
	logOK("icmp tunnel torn down")
	return nil
}

func (t *IcmpTunnel) doClean() {
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

func (t *IcmpTunnel) Status() {
	if l, err := netlink.LinkByName(t.DevName()); err == nil {
		fmt.Printf("  %s: flags=%v\n", l.Attrs().Name, l.Attrs().Flags)
	}
}
