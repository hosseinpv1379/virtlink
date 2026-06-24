// tun_bip.go — BIP tunnel (IP protocol 58 / ICMPv6 number over IPv4).
//
// "BIP" uses IPv4 raw sockets with protocol number 58 (the ICMPv6 protocol
// number) as the outer transport. This creates IPv4 packets with proto=58
// in the IP header, which confuses DPI systems that only expect proto 58
// to appear in IPv6 traffic.
//
// Architecture:
//   [TUN device] ←→ [Go userspace] ←→ [raw IPv4 socket, proto=58]
//
// Wire format:
//   outer: [IPv4 header, proto=58] [inner IP packet]
//
// No framing or encryption. The inner IP packet is the direct payload of the
// outer IPv4 packet. Receive side strips the outer IP header.
package main

import (
	"fmt"
	"net"
	"os"
	"sync/atomic"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	bipSubnet  = "10.20.44.0/24"
	bipProto   = 58 // ICMPv6 protocol number, used as transport over IPv4
)

// BipTunnel encapsulates IP traffic using IPv4 packets with protocol 58.
// Requires CAP_NET_RAW (root).
type BipTunnel struct {
	cfg     *Config
	tunFd   *os.File
	rawFd   int // raw IPv4 socket with proto=58
	done    chan struct{}
	lastSrc atomic.Value // [4]byte — server tracks client IP
}

func (t *BipTunnel) DevName() string   { return "bip-tun0" }
func (t *BipTunnel) OverlayIP() string { return overlayAddr(t.cfg, bipSubnet) }
func (t *BipTunnel) PeerIP() string    { return peerAddr(t.cfg, bipSubnet) }

func (t *BipTunnel) Up() error {
	c := t.cfg
	dev := t.DevName()
	addr := t.OverlayIP()
	peer := t.PeerIP()
	mtu := c.Tunnel.MTU
	if mtu == 0 {
		mtu = 1480 // 1500 − 20 (outer IP header)
	}

	header("bip / " + c.Mode)
	step("sysctl (via /proc/sys)...")
	applySysctl()
	step("cleanup...")
	t.doClean()

	// ── TUN device ────────────────────────────────────────────────────────────
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

	// ── raw socket, protocol 58 ───────────────────────────────────────────────
	step(fmt.Sprintf("raw socket proto=%d...", bipProto))
	t.rawFd, err = unix.Socket(unix.AF_INET, unix.SOCK_RAW, bipProto)
	if err != nil {
		return fmt.Errorf("SOCK_RAW proto=%d: %w", bipProto, err)
	}
	// 1-second receive timeout for graceful shutdown
	tv := unix.Timeval{Sec: 1, Usec: 0}
	_ = unix.SetsockoptTimeval(t.rawFd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	tuneRawSock(t.rawFd) // 4 MB socket buffers — prevents drops under burst
	logOK(fmt.Sprintf("raw proto=%d socket ready", bipProto))

	addMSS(dev)
	t.done = make(chan struct{})

	var fixedDst [4]byte
	if c.Mode == "client" {
		ip := net.ParseIP(c.RemoteIP).To4()
		copy(fixedDst[:], ip)
	}

	rawFd := t.rawFd
	tunFd := t.tunFd
	go t.rxLoop(rawFd, tunFd, fixedDst)
	go t.txLoop(rawFd, tunFd, fixedDst)

	done(dev, addr, peer,
		fmt.Sprintf("proto    : IPv4 protocol %d (ICMPv6 number, DPI confusion)", bipProto),
		fmt.Sprintf("local    : %s   remote : %s", c.LocalIP, c.RemoteIP),
		"firewall : allow IP protocol 58 between servers",
		"test     : ping -c3 "+peer,
	)
	return nil
}

// rxLoop: raw socket → TUN.
// Uses pre-allocated buffer from pool — zero per-packet allocation.
func (t *BipTunnel) rxLoop(rawFd int, tun *os.File, fixedDst [4]byte) {
	buf := getBuf()
	defer putBuf(buf)
	for {
		select {
		case <-t.done:
			return
		default:
		}
		n, from, err := unix.Recvfrom(rawFd, buf, 0)
		if err != nil {
			select {
			case <-t.done:
				return
			default:
				if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EBADF {
					continue
				}
				logWarn("bip rx: " + err.Error())
				continue
			}
		}

		// strip outer IPv4 header
		if n < 20 {
			continue
		}
		ihl := int(buf[0]&0xf) * 4
		if n <= ihl {
			continue
		}

		// filter by source IP
		if sa, ok := from.(*unix.SockaddrInet4); ok {
			if t.cfg.Mode == "server" {
				t.lastSrc.Store(sa.Addr)
			} else if sa.Addr != fixedDst {
				continue
			}
		}

		inner := buf[ihl:n]
		if _, err := tun.Write(inner); err != nil {
			select {
			case <-t.done:
				return
			default:
				logWarn("tun write: " + err.Error())
			}
		}
	}
}

// txLoop: TUN → raw socket.
// Uses pre-allocated buffer from pool — zero per-packet allocation.
func (t *BipTunnel) txLoop(rawFd int, tun *os.File, fixedDst [4]byte) {
	buf := getBuf()
	defer putBuf(buf)
	for {
		select {
		case <-t.done:
			return
		default:
		}
		n, err := tun.Read(buf)
		if err != nil {
			select {
			case <-t.done:
				return
			default:
				logWarn("tun read: " + err.Error())
				continue
			}
		}

		var dst [4]byte
		if t.cfg.Mode == "client" {
			dst = fixedDst
		} else {
			if v := t.lastSrc.Load(); v != nil {
				dst = v.([4]byte)
			} else {
				continue
			}
		}

		sa := &unix.SockaddrInet4{Addr: dst}
		if err := unix.Sendto(rawFd, buf[:n], 0, sa); err != nil {
			logDebug("bip tx: " + err.Error())
		}
	}
}

func (t *BipTunnel) Down() error {
	t.doClean()
	logOK("bip tunnel torn down")
	return nil
}

func (t *BipTunnel) doClean() {
	if t.done != nil {
		select {
		case <-t.done:
		default:
			close(t.done)
		}
		t.done = nil
	}
	if t.rawFd != 0 {
		unix.Close(t.rawFd)
		t.rawFd = 0
	}
	if t.tunFd != nil {
		t.tunFd.Close()
		t.tunFd = nil
	}
	delMSS(t.DevName())
	nlDown(t.DevName())
}

func (t *BipTunnel) Status() {
	if l, err := netlink.LinkByName(t.DevName()); err == nil {
		fmt.Printf("  %s: flags=%v\n", l.Attrs().Name, l.Attrs().Flags)
	}
}
