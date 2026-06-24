// tun_icmp.go — ICMP Echo tunnel (IP protocol 1).
//
// Performance (v2.7.6):
//   • IFF_MULTI_QUEUE TUN — one goroutine per queue (parallel TX)
//   • sendmmsg batching (32 packets) per queue
//   • Non-blocking TUN reads + poll (no stall, no duplicate sends)
//   • Lock-free sequence dedup, strict peer-IP filter
package main

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
	lastSrc atomic.Value
	peerIP  [4]byte
	localIP [4]byte
}

func (t *IcmpTunnel) DevName() string   { return "icmp-tun0" }
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

	header("icmp / " + c.Mode)
	applyPerfFromConfig(c)
	step("perf: " + perfSummary())

	step("cleanup...")
	t.doClean()
	t.stop.reset()
	t.dedup.reset()

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
	t.rawFd, err = openRawICMP()
	if err != nil {
		return fmt.Errorf("SOCK_RAW: %w", err)
	}
	_ = unix.SetNonblock(t.rawFd, true)
	logOK("raw ICMP socket ready")

	addMSS(dev)
	t.done = make(chan struct{})

	rawFd := t.rawFd
	go t.rxLoop(rawFd, t.tun.Fd0())
	for _, qfd := range t.tun.fds {
		go t.txLoop(rawFd, qfd)
	}

	done(dev, addr, peer,
		fmt.Sprintf("transport : ICMP ×%d queues (batch TX)", t.tun.QueueCount()),
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

// txLoop serves one TUN queue: non-blocking drain + sendmmsg batches.
func (t *IcmpTunnel) txLoop(rawFd int, qfd *os.File) {
	_ = unix.SetNonblock(int(qfd.Fd()), true)
	tunFD := int(qfd.Fd())

	scratch := getICMPFrame()
	defer putICMPFrame(scratch)
	scratchPayload := scratch[icmpHdrLen:]

	var batch icmpTxBatch

	for !t.stop.stopped() {
		batch.reset()

		for batch.n < perfBatchSize() {
			n, err := tunReadNB(qfd, scratchPayload)
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				break
			}
			if err != nil || n == 0 {
				if err != nil && !t.stop.stopped() {
					logWarn("tun read: " + err.Error())
				}
				break
			}
			dst, ok := t.resolveDst()
			if !ok {
				continue
			}
			frame := getICMPFrame()
			seq := uint16(t.seq.Add(1))
			pkt := buildICMPFrame(frame, icmpTunID, seq, scratchPayload[:n])
			batch.add(frame, len(pkt), dst)
		}

		if batch.n == 0 {
			_ = pollFD(tunFD, unix.POLLIN, perfPollMs())
			continue
		}

		icmpSendBatch(rawFd, &batch)
		for i := 0; i < batch.n; i++ {
			putICMPFrame(batch.frames[i])
			batch.frames[i] = nil
		}
	}
}

func (t *IcmpTunnel) rxLoop(rawFd int, tun *os.File) {
	buf := getBuf()
	defer putBuf(buf)
	peer, local := t.peerIP, t.localIP

	for !t.stop.stopped() {
		n, from, err := unix.Recvfrom(rawFd, buf, 0)
		if err != nil {
			if t.stop.stopped() {
				return
			}
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				_ = pollFD(rawFd, unix.POLLIN, perfPollMs())
				continue
			}
			if err == unix.EINTR {
				continue
			}
			logWarn("icmp rx: " + err.Error())
			continue
		}
		sa, ok := from.(*unix.SockaddrInet4)
		if !ok || sa.Addr == local || sa.Addr != peer {
			continue
		}
		if n < 20 {
			continue
		}
		ihl := int(buf[0]&0xf) * 4
		if n < ihl+8 {
			continue
		}
		icmp := buf[ihl:n]
		if icmp[0] != icmpEchoReq || binary.BigEndian.Uint16(icmp[4:6]) != icmpTunID {
			continue
		}
		seq := binary.BigEndian.Uint16(icmp[6:8])
		if t.dedup.dup(seq) {
			continue
		}
		if t.cfg.Mode == "server" {
			t.lastSrc.Store(sa.Addr)
		}
		if err := tunWrite(tun, icmp[8:]); err != nil && !t.stop.stopped() {
			logWarn("tun write: " + err.Error())
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
