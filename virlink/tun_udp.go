// tun_udp.go — plain UDP tunnel (no encryption).
//
// Performance (v2.6):
//   • tunWorkers (4) UDP sockets with SO_REUSEPORT — kernel load-balances RX
//   • Round-robin TX across sockets — multi-core scaling
//   • Zero per-packet allocation (buffer pool)
//   • 16 MB socket buffers
package main

import (
	"fmt"
	"net"
	"os"
	"sync/atomic"

	"github.com/vishvananda/netlink"
)

const udpRawSubnet = "10.20.42.0/24"

type UdpTunnel struct {
	cfg      *Config
	tunFd    *os.File
	udpConns []*net.UDPConn
	done     chan struct{}
	stop     stoppedFlag
	lastPeer atomic.Value // *net.UDPAddr
	rr       rrCounter
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
		mtu = 1472
	}

	header("udp / " + c.Mode)
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

	step(fmt.Sprintf("UDP sockets ×%d :%d (SO_REUSEPORT)...", tunWorkers, port))
	if c.Mode == "server" {
		t.udpConns, err = listenUDPWorkers(port)
	} else {
		t.udpConns, err = dialUDPWorkers(c.RemoteIP, port)
	}
	if err != nil {
		return fmt.Errorf("udp :%d: %w", port, err)
	}
	for _, conn := range t.udpConns {
		tuneUDPConn(conn)
	}
	logOK(fmt.Sprintf("UDP ×%d :%d", len(t.udpConns), port))

	addMSS(dev)
	t.done = make(chan struct{})

	var fixedPeer *net.UDPAddr
	if c.Mode == "client" {
		fixedPeer = &net.UDPAddr{IP: net.ParseIP(c.RemoteIP), Port: port}
		t.lastPeer.Store(fixedPeer)
	}

	tun := t.tunFd
	for _, conn := range t.udpConns {
		go t.rxLoop(conn, tun)
	}
	go t.txLoop(tun, fixedPeer)

	done(dev, addr, peer,
		fmt.Sprintf("transport : UDP ×%d :%d", tunWorkers, port),
		"test      : ping -c3 "+peer,
	)
	return nil
}

func (t *UdpTunnel) rxLoop(conn *net.UDPConn, tun *os.File) {
	buf := getBuf()
	defer putBuf(buf)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if t.stop.stopped() {
				return
			}
			logWarn("udp rx: " + err.Error())
			continue
		}
		t.lastPeer.Store(src)
		if _, err := tun.Write(buf[:n]); err != nil {
			if t.stop.stopped() {
				return
			}
			logWarn("tun write: " + err.Error())
		}
	}
}

func (t *UdpTunnel) txLoop(tun *os.File, fixed *net.UDPAddr) {
	buf := getBuf()
	defer putBuf(buf)
	conns := t.udpConns
	for {
		n, err := tun.Read(buf)
		if err != nil {
			if t.stop.stopped() {
				return
			}
			logWarn("tun read: " + err.Error())
			continue
		}
		dst := fixed
		if dst == nil {
			if p, ok := t.lastPeer.Load().(*net.UDPAddr); ok && p != nil {
				dst = p
			} else {
				continue
			}
		}
		idx := t.rr.next() % len(conns)
		if _, err := conns[idx].WriteToUDP(buf[:n], dst); err != nil {
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
	t.stop.stop()
	if t.done != nil {
		select {
		case <-t.done:
		default:
			close(t.done)
		}
		t.done = nil
	}
	closeUDPs(t.udpConns)
	t.udpConns = nil
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
