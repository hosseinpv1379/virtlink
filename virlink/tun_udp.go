// tun_udp.go — plain UDP tunnel (no encryption).
//
// Single UDP socket for RX (SO_REUSEPORT multi-socket caused duplicate delivery
// on some kernels).  TX uses a worker pool fed by one TUN reader for parallelism.
package main

import (
	"fmt"
	"net"
	"os"
	"sync/atomic"

	"github.com/vishvananda/netlink"
)

const udpRawSubnet = "10.20.42.0/24"

type udpTxJob struct {
	buf []byte
	n   int
}

type UdpTunnel struct {
	cfg      *Config
	tunFd    *os.File
	udpConn  *net.UDPConn
	txCh     chan udpTxJob
	done     chan struct{}
	stop     stoppedFlag
	lastPeer atomic.Value // *net.UDPAddr
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

	step(fmt.Sprintf("UDP socket :%d...", port))
	t.udpConn, err = net.ListenUDP("udp4", &net.UDPAddr{Port: port})
	if err != nil {
		return fmt.Errorf("udp :%d: %w", port, err)
	}
	tuneUDPConn(t.udpConn)
	if c.Mode == "client" {
		dst := &net.UDPAddr{IP: net.ParseIP(c.RemoteIP), Port: port}
		t.lastPeer.Store(dst)
		_ = connectUDP(t.udpConn, dst)
	}
	logOK(fmt.Sprintf("UDP :%d  tx_workers=%d", port, tunWorkers))

	addMSS(dev)
	t.done = make(chan struct{})
	t.txCh = make(chan udpTxJob, 512)

	var fixedPeer *net.UDPAddr
	if c.Mode == "client" {
		fixedPeer = &net.UDPAddr{IP: net.ParseIP(c.RemoteIP), Port: port}
	}

	conn := t.udpConn
	tun := t.tunFd
	go t.rxLoop(conn, tun)
	go t.txReader(tun)
	for i := 0; i < tunWorkers; i++ {
		go t.txWorker(conn, fixedPeer)
	}

	done(dev, addr, peer,
		fmt.Sprintf("transport : UDP :%d  tx_workers=%d", port, tunWorkers),
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

// txReader reads from TUN and hands copies to worker pool.
func (t *UdpTunnel) txReader(tun *os.File) {
	buf := getBuf()
	defer putBuf(buf)
	for {
		n, err := tun.Read(buf)
		if err != nil {
			if t.stop.stopped() {
				return
			}
			logWarn("tun read: " + err.Error())
			continue
		}
		pkt := getBuf()
		copy(pkt, buf[:n])
		select {
		case t.txCh <- udpTxJob{pkt, n}:
		default:
			// queue full — drop back-pressure frame, keep tunnel alive
			putBuf(pkt)
		}
		if t.stop.stopped() {
			return
		}
	}
}

func (t *UdpTunnel) txWorker(conn *net.UDPConn, fixed *net.UDPAddr) {
	for job := range t.txCh {
		dst := fixed
		if dst == nil {
			if p, ok := t.lastPeer.Load().(*net.UDPAddr); ok && p != nil {
				dst = p
			} else {
				putBuf(job.buf)
				continue
			}
		}
		if _, err := conn.WriteToUDP(job.buf[:job.n], dst); err != nil {
			logDebug("udp tx: " + err.Error())
		}
		putBuf(job.buf)
	}
}

func (t *UdpTunnel) Down() error {
	t.doClean()
	logOK("udp tunnel torn down")
	return nil
}

func (t *UdpTunnel) doClean() {
	t.stop.stop()
	if t.txCh != nil {
		close(t.txCh)
		t.txCh = nil
	}
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
