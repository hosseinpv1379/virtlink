// tun_udp.go — plain UDP tunnel.
//
// Performance (v2.7): IFF_MULTI_QUEUE TUN (parallel tx readers), single UDP socket,
// connected client socket, 16 MB buffers.
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
	tun      *TunDev
	udpConn  *net.UDPConn
	lockFd   *os.File
	done     chan struct{}
	stop     stoppedFlag
	lastPeer atomic.Value
	peerIP   [4]byte
	localIP  [4]byte
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
	t.peerIP = ipTo4(c.RemoteIP)
	t.localIP = ipTo4(c.LocalIP)

	header("udp / " + c.Mode)
	applyPerfFromConfig(c)
	t.doClean()
	t.stop.reset()

	var err error
	t.lockFd, err = acquireTunnelLock(dev)
	if err != nil {
		return err
	}

	t.tun, err = openTunMulti(dev, perfTunQueues())
	if err != nil {
		return fmt.Errorf("tun: %w", err)
	}
	l, _ := netlink.LinkByName(dev)
	netlink.LinkSetMTU(l, mtu)
	a, _ := netlink.ParseAddr(addr)
	netlink.AddrAdd(l, a)
	netlink.LinkSetUp(l)
	logOK(fmt.Sprintf("%s  %s  queues=%d", dev, addr, t.tun.QueueCount()))

	step(fmt.Sprintf("tuning (%s)...", tuningModeLabel(c)))
	applyTunnelTuning(c, dev)

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
	logOK(fmt.Sprintf("UDP :%d", port))

	addMSS(dev)
	t.done = make(chan struct{})

	conn := t.udpConn
	go t.rxLoop(conn, t.tun.Fd0())
	go t.txPollLoop(conn)

	done(dev, addr, peer, fmt.Sprintf("transport : UDP :%d  poller×1", port))
	return nil
}

func (t *UdpTunnel) rxLoop(conn *net.UDPConn, tun *os.File) {
	buf := getBuf()
	defer putBuf(buf)
	peer, local := t.peerIP, t.localIP
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if t.stop.stopped() {
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
			statInc(statUDPRxDrop)
			continue
		}
		if t.cfg.Mode == "client" && sip != peer {
			statInc(statUDPRxDrop)
			continue
		}
		if t.cfg.Mode == "server" {
			t.lastPeer.Store(src)
		}
		statInc(statUDPRxRecv)
		if err := tunWrite(tun, buf[:n]); err != nil && !t.stop.stopped() {
			logWarn("tun write: " + err.Error())
		} else {
			statInc(statUDPRxWrite)
		}
	}
}

func (t *UdpTunnel) txPollLoop(conn *net.UDPConn) {
	poller := newTunPoller(t.tun, &t.stop)
	defer poller.close()

	poller.Run(
		func() { statInc(statUDPTxPoll) },
		func(pkt []byte, n int) bool {
			statInc(statUDPTxRead)
			var dst *net.UDPAddr
			if p, ok := t.lastPeer.Load().(*net.UDPAddr); ok && p != nil {
				dst = p
			}
			if dst == nil {
				statInc(statUDPTxNoDst)
				return true
			}
			if _, err := conn.WriteToUDP(pkt[:n], dst); err != nil && !t.stop.stopped() {
				logDebug("udp tx: " + err.Error())
			} else if err == nil {
				statInc(statUDPTxSend)
			}
			return !t.stop.stopped()
		},
	)
}

func (t *UdpTunnel) Down() error {
	t.doClean()
	logOK("udp tunnel torn down")
	return nil
}

func (t *UdpTunnel) doClean() {
	restoreTunnelTuning()
	t.stop.stop()
	if t.done != nil {
		close(t.done)
		t.done = nil
	}
	if t.udpConn != nil {
		t.udpConn.Close()
		t.udpConn = nil
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

func (t *UdpTunnel) Status() {
	if l, err := netlink.LinkByName(t.DevName()); err == nil {
		fmt.Printf("  %s: flags=%v\n", l.Attrs().Name, l.Attrs().Flags)
	}
}
