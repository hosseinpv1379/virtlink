// tun_icmp.go — ICMP Echo tunnel (IP protocol 1).
//
// Single raw socket.  Strict peer-IP filter rejects own outbound loopback
// (Linux delivers sent packets back to the same raw socket).  Sequence
// dedup catches any remaining duplicate delivery.
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	icmpSubnet  = "10.20.43.0/24"
	icmpTunID   = uint16(0xCAFE)
	icmpEchoReq = 8
)

// icmpSeqDedup tracks recently seen outer ICMP sequence numbers from the peer.
type icmpSeqDedup struct {
	mu   sync.Mutex
	ring [512]uint16
	idx  int
}

func (d *icmpSeqDedup) isDup(seq uint16) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, s := range d.ring {
		if s == seq {
			return true
		}
	}
	d.ring[d.idx%512] = seq
	d.idx++
	return false
}

type IcmpTunnel struct {
	cfg     *Config
	tunFd   *os.File
	rawFd   int
	lockFd  *os.File
	done    chan struct{}
	stop    stoppedFlag
	seq     atomic.Uint32
	dedup   icmpSeqDedup
	lastSrc atomic.Value // [4]byte — server only
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
	step("sysctl (via /proc/sys)...")
	applySysctl()
	step("cleanup...")
	t.doClean()

	// Prevent duplicate tunnel instances (each extra process = duplicate packets).
	step("instance lock...")
	var err error
	t.lockFd, err = acquireTunnelLock(dev)
	if err != nil {
		return err
	}
	logOK("instance lock acquired")

	step(fmt.Sprintf("TUN device %s...", dev))
	t.tunFd, err = openTunDev(dev)
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
	logOK(fmt.Sprintf("%s  %s  MTU=%d", dev, addr, mtu))

	step("raw ICMP socket...")
	t.rawFd, err = openRawICMP()
	if err != nil {
		return fmt.Errorf("SOCK_RAW IPPROTO_ICMP: %w", err)
	}
	logOK("raw ICMP socket ready")

	addMSS(dev)
	t.done = make(chan struct{})

	rawFd := t.rawFd
	tun := t.tunFd
	go t.rxLoop(rawFd, tun)
	go t.txLoop(rawFd, tun)

	done(dev, addr, peer,
		"proto    : ICMP Echo (peer-filtered)",
		"id       : 0xCAFE",
		"filter   : peer="+c.RemoteIP+" only",
		"test     : ping -c3 "+peer,
	)
	return nil
}

func (t *IcmpTunnel) rxLoop(rawFd int, tun *os.File) {
	buf := getBuf()
	defer putBuf(buf)
	peer := t.peerIP
	local := t.localIP
	for {
		n, from, err := unix.Recvfrom(rawFd, buf, 0)
		if err != nil {
			if t.stop.stopped() {
				return
			}
			if err == unix.EINTR {
				continue
			}
			logWarn("icmp rx: " + err.Error())
			continue
		}
		sa, ok := from.(*unix.SockaddrInet4)
		if !ok {
			continue
		}
		// Drop own outbound packets echoed back by the kernel.
		if sa.Addr == local {
			continue
		}
		// Only accept tunnel packets from the configured peer public IP.
		if sa.Addr != peer {
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
		if icmp[0] != icmpEchoReq {
			continue
		}
		if binary.BigEndian.Uint16(icmp[4:6]) != icmpTunID {
			continue
		}
		seq := binary.BigEndian.Uint16(icmp[6:8])
		if t.dedup.isDup(seq) {
			continue
		}
		if t.cfg.Mode == "server" {
			t.lastSrc.Store(sa.Addr)
		}
		if _, err := tun.Write(icmp[8:]); err != nil {
			if t.stop.stopped() {
				return
			}
			logWarn("tun write: " + err.Error())
		}
	}
}

func (t *IcmpTunnel) txLoop(rawFd int, tun *os.File) {
	buf := getBuf()
	frame := getICMPFrame()
	defer putBuf(buf)
	defer putICMPFrame(frame)

	for {
		n, err := tun.Read(buf)
		if err != nil {
			if t.stop.stopped() {
				return
			}
			logWarn("tun read: " + err.Error())
			continue
		}
		var dst [4]byte
		if t.cfg.Mode == "client" {
			dst = t.peerIP
		} else if v := t.lastSrc.Load(); v != nil {
			dst = v.([4]byte)
		} else {
			continue
		}
		seq := uint16(t.seq.Add(1))
		pkt := buildICMPFrame(frame, icmpTunID, seq, buf[:n])
		sa := &unix.SockaddrInet4{Addr: dst}
		if err := unix.Sendto(rawFd, pkt, 0, sa); err != nil {
			logDebug("icmp tx: " + err.Error())
		}
	}
}

func (t *IcmpTunnel) Down() error {
	t.doClean()
	logOK("icmp tunnel torn down")
	return nil
}

func (t *IcmpTunnel) doClean() {
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
	if t.tunFd != nil {
		t.tunFd.Close()
		t.tunFd = nil
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
