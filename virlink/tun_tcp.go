// tun_tcp.go — TCP tunnel.
//
// Performance (v2.7): multi-queue TUN tx readers + tunQueues parallel TCP streams.
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/vishvananda/netlink"
)

const tcpSubnet = "10.20.41.0/24"

type TcpTunnel struct {
	cfg    *Config
	tun    *TunDev
	ln     net.Listener
	conns  [tunQueues]atomic.Pointer[net.Conn]
	done   chan struct{}
	stop   stoppedFlag
	rr     rrCounter
}

func (t *TcpTunnel) DevName() string   { return "tcp-tun0" }
func (t *TcpTunnel) OverlayIP() string { return overlayAddr(t.cfg, tcpSubnet) }
func (t *TcpTunnel) PeerIP() string    { return peerAddr(t.cfg, tcpSubnet) }

func (t *TcpTunnel) Up() error {
	c := t.cfg
	dev := t.DevName()
	addr := t.OverlayIP()
	peer := t.PeerIP()
	port := c.Transport.Port
	mtu := c.Tunnel.MTU
	if mtu == 0 {
		mtu = 1460
	}

	header("tcp / " + c.Mode)
	step("cleanup...")
	t.doClean()

	var err error
	step(fmt.Sprintf("TUN device %s ×%d queues...", dev, tunQueues))
	t.tun, err = openTunMulti(dev, tunQueues)
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
	logOK(fmt.Sprintf("%s  %s  MTU=%d  queues=%d", dev, addr, mtu, tunQueues))

	step(fmt.Sprintf("tuning (%s)...", tuningModeLabel(c)))
	applyTunnelTuning(c, dev)

	addMSS(dev)
	t.done = make(chan struct{})

	tun0 := t.tun.Fd0()
	for _, q := range t.tun.fds {
		go t.txLoop(q)
	}

	if c.Mode == "server" {
		t.ln, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			return fmt.Errorf("tcp listen :%d: %w", port, err)
		}
		logOK(fmt.Sprintf("TCP listening :%d  streams=%d", port, tunQueues))
		go t.acceptLoop(tun0)
	} else {
		go t.connectLoop(tun0)
	}

	done(dev, addr, peer,
		fmt.Sprintf("transport : TCP ×%d streams  queues=%d :%d", tunQueues, tunQueues, port),
		"reconnect : automatic (client retries every 3 s)",
		"test      : ping -c3 "+peer,
	)
	return nil
}

func (t *TcpTunnel) pickConn() net.Conn {
	for i := 0; i < tunQueues; i++ {
		idx := t.rr.next() % tunQueues
		if c := t.conns[idx].Load(); c != nil {
			return *c
		}
	}
	return nil
}

func (t *TcpTunnel) txLoop(tun *os.File) {
	buf := getBuf()
	defer putBuf(buf)
	for {
		n, err := tunRead(tun, buf)
		if err != nil {
			if t.stop.stopped() {
				return
			}
			logWarn("tun read: " + err.Error())
			continue
		}
		c := t.pickConn()
		if c == nil {
			continue
		}
		if err := tcpWriteFrame(c, buf[:n]); err != nil {
			logDebug("tcp tx: " + err.Error())
			t.clearConn(c)
		}
	}
}

func (t *TcpTunnel) clearConn(c net.Conn) {
	for i := range t.conns {
		if p := t.conns[i].Load(); p != nil && *p == c {
			_ = c.Close()
			t.conns[i].Store(nil)
			return
		}
	}
}

func (t *TcpTunnel) setConn(slot int, c net.Conn) {
	if old := t.conns[slot].Swap(&c); old != nil && *old != c {
		_ = (*old).Close()
	}
}

func (t *TcpTunnel) acceptLoop(tun *os.File) {
	slot := 0
	for {
		conn, err := t.ln.Accept()
		if err != nil {
			if t.stop.stopped() {
				return
			}
			logWarn("tcp accept: " + err.Error())
			time.Sleep(100 * time.Millisecond)
			continue
		}
		tuneTCPConn(conn)
		logInfo(fmt.Sprintf("tcp: client connected from %s (stream %d)", conn.RemoteAddr(), slot%tunQueues))
		idx := slot % tunQueues
		slot++
		t.setConn(idx, conn)
		go t.rxLoop(conn, tun, idx)
	}
}

func (t *TcpTunnel) connectLoop(tun *os.File) {
	addr := fmt.Sprintf("%s:%d", t.cfg.RemoteIP, t.cfg.Transport.Port)
	for s := 0; s < tunQueues; s++ {
		go t.connectOne(tun, addr, s)
	}
	select {
	case <-t.done:
	}
}

func (t *TcpTunnel) connectOne(tun *os.File, addr string, slot int) {
	for {
		if t.stop.stopped() {
			return
		}
		conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			logWarn(fmt.Sprintf("tcp connect %s stream %d: %v — retry in 3s", addr, slot, err))
			select {
			case <-t.done:
				return
			case <-time.After(3 * time.Second):
				continue
			}
		}
		tuneTCPConn(conn)
		logOK(fmt.Sprintf("tcp: stream %d connected to %s", slot, addr))
		t.setConn(slot, conn)
		t.rxLoop(conn, tun, slot)
		t.conns[slot].Store(nil)
		select {
		case <-t.done:
			return
		case <-time.After(time.Second):
		}
	}
}

func (t *TcpTunnel) rxLoop(conn net.Conn, tun *os.File, slot int) {
	defer conn.Close()
	buf := getBuf()
	defer putBuf(buf)
	var hdr [2]byte
	for {
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			if !t.stop.stopped() {
				logDebug(fmt.Sprintf("tcp rx stream %d: %v", slot, err))
			}
			t.conns[slot].CompareAndSwap(&conn, nil)
			return
		}
		n := int(binary.BigEndian.Uint16(hdr[:]))
		if n == 0 || n > len(buf) {
			logWarn(fmt.Sprintf("tcp rx: invalid frame len %d", n))
			return
		}
		if _, err := io.ReadFull(conn, buf[:n]); err != nil {
			if !t.stop.stopped() {
				logDebug(fmt.Sprintf("tcp rx read stream %d: %v", slot, err))
			}
			return
		}
		if _, err := tun.Write(buf[:n]); err != nil {
			if t.stop.stopped() {
				return
			}
			logWarn("tun write: " + err.Error())
		}
	}
}

func tcpWriteFrame(conn net.Conn, data []byte) error {
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(data)))
	_, err := (&net.Buffers{hdr[:], data}).WriteTo(conn)
	return err
}

func (t *TcpTunnel) Down() error {
	t.doClean()
	logOK("tcp tunnel torn down")
	return nil
}

func (t *TcpTunnel) doClean() {
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
	if t.ln != nil {
		_ = t.ln.Close()
		t.ln = nil
	}
	for i := range t.conns {
		if p := t.conns[i].Load(); p != nil {
			_ = (*p).Close()
			t.conns[i].Store(nil)
		}
	}
	if t.tun != nil {
		t.tun.Close()
		t.tun = nil
	}
	delMSS(t.DevName())
	nlDown(t.DevName())
}

func (t *TcpTunnel) Status() {
	if l, err := netlink.LinkByName(t.DevName()); err == nil {
		fmt.Printf("  %s: flags=%v\n", l.Attrs().Name, l.Attrs().Flags)
	}
}
