// tun_udp.go — plain UDP tunnel (no encryption, no obfuscation).
//
// Architecture:
//   [TUN device] ←→ [Go userspace] ←→ [UDP socket]
//
// IP packets read from TUN are sent as raw UDP datagrams.
// Received UDP datagrams are written directly to TUN.
//
// Server dynamically tracks client address from incoming packets.
// No framing overhead — one UDP datagram = one IP packet.
package main

import (
	"fmt"
	"net"
	"os"
	"sync/atomic"

	"github.com/vishvananda/netlink"
)

const udpRawSubnet = "10.20.42.0/24"

// UdpTunnel is a plain UDP tunnel with a TUN device.
// Unlike udp-obfs, there is no AES encryption or protocol masking.
type UdpTunnel struct {
	cfg      *Config
	tunFd    *os.File
	udpConn  *net.UDPConn
	done     chan struct{}
	lastPeer atomic.Value // *net.UDPAddr — server tracks client dynamically
}

func (t *UdpTunnel) DevName() string   { return "udp-tun0" }
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
		mtu = 1472 // 1500 − 20 (IP) − 8 (UDP)
	}

	header("udp / " + c.Mode)
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
	logOK(fmt.Sprintf("%s  %s  MTU=%d", dev, addr, mtu))

	// ── UDP socket ────────────────────────────────────────────────────────────
	step(fmt.Sprintf("UDP socket :%d...", port))
	t.udpConn, err = net.ListenUDP("udp4", &net.UDPAddr{Port: port})
	if err != nil {
		return fmt.Errorf("udp :%d: %w", port, err)
	}
	tuneUDPConn(t.udpConn) // 4 MB socket buffers — prevents kernel drops under burst
	logOK(fmt.Sprintf("UDP :%d", port))

	addMSS(dev)
	t.done = make(chan struct{})

	// client knows where to send; server learns from first packet
	var fixedPeer *net.UDPAddr
	if c.Mode == "client" {
		fixedPeer = &net.UDPAddr{IP: net.ParseIP(c.RemoteIP), Port: port}
		t.lastPeer.Store(fixedPeer)
	}

	// Capture local refs — doClean() nils these fields, goroutines must not race on them
	go t.rxLoop(t.udpConn, t.tunFd, mtu)
	go t.txLoop(t.udpConn, t.tunFd, fixedPeer)

	done(dev, addr, peer,
		fmt.Sprintf("transport : UDP :%d  (no encryption)", port),
		"test      : ping -c3 "+peer,
	)
	return nil
}

// rxLoop: UDP socket → TUN
// Uses pre-allocated buffer from pool — zero per-packet allocation.
func (t *UdpTunnel) rxLoop(conn *net.UDPConn, tun *os.File, mtu int) {
	buf := getBuf()
	defer putBuf(buf)
	_ = mtu // buf is already sized for any UDP datagram
	for {
		select {
		case <-t.done:
			return
		default:
		}
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-t.done:
				return
			default:
				logWarn("udp rx: " + err.Error())
				continue
			}
		}
		t.lastPeer.Store(src)
		if _, err := tun.Write(buf[:n]); err != nil {
			select {
			case <-t.done:
				return
			default:
				logWarn("tun write: " + err.Error())
			}
		}
	}
}

// txLoop: TUN → UDP socket
// Uses pre-allocated buffer from pool — zero per-packet allocation.
func (t *UdpTunnel) txLoop(conn *net.UDPConn, tun *os.File, fixed *net.UDPAddr) {
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
		dst := fixed
		if dst == nil {
			if p, ok := t.lastPeer.Load().(*net.UDPAddr); ok && p != nil {
				dst = p
			} else {
				continue
			}
		}
		if _, err := conn.WriteToUDP(buf[:n], dst); err != nil {
			logDebug("udp tx: " + err.Error())
		}
	}
}

func (t *UdpTunnel) Down() error {
	t.doClean()
	logOK("udp tunnel torn down")
	return nil
}

func (t *UdpTunnel) doClean() {
	if t.done != nil {
		select {
		case <-t.done:
		default:
			close(t.done)
		}
		t.done = nil
	}
	if t.udpConn != nil {
		t.udpConn.Close()
		t.udpConn = nil
	}
	if t.tunFd != nil {
		t.tunFd.Close()
		t.tunFd = nil
	}
	delMSS(t.DevName())
	nlDown(t.DevName())
}

func (t *UdpTunnel) Status() {
	if l, err := netlink.LinkByName(t.DevName()); err == nil {
		fmt.Printf("  %s: flags=%v\n", l.Attrs().Name, l.Attrs().Flags)
	}
}
