// tun_tcp.go — TCP tunnel.
//
// Performance (v2.7): multi-queue TUN tx readers + parallel TCP streams ([tuning] tcp_streams).
package virlink

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
	conns  [maxPerfQueues]atomic.Pointer[net.Conn]
	done   chan struct{}
	stop   stoppedFlag
}

func (t *TcpTunnel) DevName() string   { return tunnelDevName(t.cfg, "tcp-tun0") }
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
	applyPerfFromConfig(c)
	step("perf: " + perfSummary())
	step("cleanup...")
	t.doClean()
	t.stop.reset()

	var err error
	step(fmt.Sprintf("TUN device %s ×%d queues...", dev, perfTunQueues()))
	t.tun, err = openTunMulti(dev, perfTunQueues())
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
	logOK(fmt.Sprintf("%s  %s  MTU=%d  queues=%d", dev, addr, mtu, t.tun.QueueCount()))

	step(fmt.Sprintf("tuning (%s)...", tuningModeLabel(c)))
	applyTunnelTuning(c, dev)

	if err := tcpTunnelWireUp(c); err != nil {
		return err
	}

	addMSS(dev)
	t.done = make(chan struct{})

	tun0 := t.tun.Fd0()
	go t.txPollLoop()

	streams := perfTcpStreams()
	if c.Mode == "server" {
		t.ln, err = listenTCPWire(c, port)
		if err != nil {
			return fmt.Errorf("tcp listen :%d: %w", port, err)
		}
		logOK(fmt.Sprintf("TCP listening %s  streams=%d", t.ln.Addr(), streams))
		go t.acceptLoop(tun0)
	} else {
		go t.connectLoop(tun0)
	}

	done(dev, addr, peer,
		fmt.Sprintf("transport : TCP ×%d streams  poller×1 :%d", streams, port),
		wireTCPDoneExtra(c),
		"reconnect : automatic (client retries every 3 s)",
		"test      : ping -c3 "+peer,
	)
	return nil
}

func tcpStreamSlot(data []byte, streams int) int {
	if streams <= 1 {
		return 0
	}
	return int(hashIPPacket(data) % uint32(streams))
}

func (t *TcpTunnel) pickConn(data []byte) net.Conn {
	n := perfTcpStreams()
	slot := tcpStreamSlot(data, n)
	if c := t.conns[slot].Load(); c != nil {
		return *c
	}
	for i := 0; i < n; i++ {
		if c := t.conns[i].Load(); c != nil {
			return *c
		}
	}
	return nil
}

func (t *TcpTunnel) txPollLoop() {
	poller := newTunPoller(t.tun, &t.stop)
	defer poller.close()

	poller.Run(nil, func(pkt []byte, n int) bool {
		statInc(statTCPTxRead)
		c := t.pickConn(pkt[:n])
		if c == nil {
			statInc(statTCPTxNoConn)
			return true
		}
		if err := tcpWriteFrame(c, pkt[:n]); err != nil {
			logDebug("tcp tx: " + err.Error())
			t.clearConn(c)
		} else {
			statInc(statTCPTxSend)
		}
		return !t.stop.stopped()
	})
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
		idx := slot % perfTcpStreams()
		logInfo(fmt.Sprintf("[wire] tcp accept stream %d  wire peer=%s",
			idx, conn.RemoteAddr()))
		slot++
		t.setConn(idx, conn)
		go t.rxLoop(conn, tun, idx)
	}
}

func (t *TcpTunnel) connectLoop(tun *os.File) {
	for s := 0; s < perfTcpStreams(); s++ {
		go t.connectOne(tun, s)
	}
	select {
	case <-t.done:
	}
}

func (t *TcpTunnel) connectOne(tun *os.File, slot int) {
	tcpConnectStagger(slot)
	for {
		if t.stop.stopped() {
			return
		}
		conn, err := dialTCPWire(t.cfg, 10*time.Second)
		if err != nil {
			logTcpStreamRetry("tcp", slot, err)
			select {
			case <-t.done:
				return
			case <-time.After(3 * time.Second):
				continue
			}
		}
		tuneTCPConn(conn)
		noteTcpWireConnected()
		logOK(fmt.Sprintf("tcp: stream %d up  %s ↔ %s", slot, conn.LocalAddr(), conn.RemoteAddr()))
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
		statInc(statTCPRxFrame)
		if _, err := tun.Write(buf[:n]); err != nil {
			if t.stop.stopped() {
				return
			}
			logWarn("tun write: " + err.Error())
		} else {
			statInc(statTCPRxWrite)
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
	resetTcpWireConnectState()
	tcpTunnelWireDown(t.cfg)
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
