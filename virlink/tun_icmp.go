// tun_icmp.go — ICMP Echo tunnel (IP protocol 1).
//
// Performance (v2.6):
//   • Zero per-packet heap allocation (in-place ICMP build + frame pool)
//   • tunWorkers raw sockets with SO_REUSEPORT
//   • Blocking recv (no 1 s poll timeout)
//   • 16 MB socket buffers
package main

import (
	"encoding/binary"
	"fmt"
	"net"
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
	tunFd   *os.File
	rawFds  []int
	done    chan struct{}
	stop    stoppedFlag
	seq     atomic.Uint32
	lastSrc atomic.Value // [4]byte
	rr      rrCounter
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

	header("icmp / " + c.Mode)
	step("sysctl (via /proc/sys)...")
	applySysctl()
	step("cleanup...")
	t.doClean()

	step(fmt.Sprintf("TUN device %s...", dev))
	var err error
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

	step(fmt.Sprintf("raw ICMP sockets ×%d (SO_REUSEPORT)...", tunWorkers))
	t.rawFds, err = openRawICMPWorkers()
	if err != nil {
		return fmt.Errorf("SOCK_RAW IPPROTO_ICMP: %w", err)
	}
	logOK(fmt.Sprintf("raw ICMP ×%d ready", len(t.rawFds)))

	addMSS(dev)
	t.done = make(chan struct{})

	var fixedDst [4]byte
	if c.Mode == "client" {
		ip := net.ParseIP(c.RemoteIP).To4()
		copy(fixedDst[:], ip)
	}

	tun := t.tunFd
	for _, fd := range t.rawFds {
		go t.rxLoop(fd, tun, fixedDst)
	}
	go t.txLoop(tun, fixedDst)

	done(dev, addr, peer,
		"proto    : ICMP Echo ×"+fmt.Sprint(tunWorkers),
		"id       : 0xCAFE",
		"test     : ping -c3 "+peer,
	)
	return nil
}

func (t *IcmpTunnel) rxLoop(rawFd int, tun *os.File, fixedDst [4]byte) {
	buf := getBuf()
	defer putBuf(buf)
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
		if t.cfg.Mode == "server" {
			if sa, ok := from.(*unix.SockaddrInet4); ok {
				t.lastSrc.Store(sa.Addr)
			}
		} else if sa, ok := from.(*unix.SockaddrInet4); ok && sa.Addr != fixedDst {
			continue
		}
		payload := icmp[8:]
		if _, err := tun.Write(payload); err != nil {
			if t.stop.stopped() {
				return
			}
			logWarn("tun write: " + err.Error())
		}
	}
}

func (t *IcmpTunnel) txLoop(tun *os.File, fixedDst [4]byte) {
	buf := getBuf()
	frame := getICMPFrame()
	defer putBuf(buf)
	defer putICMPFrame(frame)

	fds := t.rawFds
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
			dst = fixedDst
		} else if v := t.lastSrc.Load(); v != nil {
			dst = v.([4]byte)
		} else {
			continue
		}
		seq := uint16(t.seq.Add(1))
		pkt := buildICMPFrame(frame, icmpTunID, seq, buf[:n])
		idx := t.rr.next() % len(fds)
		sa := &unix.SockaddrInet4{Addr: dst}
		if err := unix.Sendto(fds[idx], pkt, 0, sa); err != nil {
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
	closeFDs(t.rawFds)
	t.rawFds = nil
	if t.tunFd != nil {
		t.tunFd.Close()
		t.tunFd = nil
	}
	delMSS(t.DevName())
	nlDown(t.DevName())
}

func (t *IcmpTunnel) Status() {
	if l, err := netlink.LinkByName(t.DevName()); err == nil {
		fmt.Printf("  %s: flags=%v\n", l.Attrs().Name, l.Attrs().Flags)
	}
}
