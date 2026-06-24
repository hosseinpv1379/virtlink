// tun_tcp.go — TCP tunnel.
//
// Architecture:
//   [TUN device] ←→ [Go userspace] ←→ [TCP socket]
//
// Framing: [uint16 big-endian length (2 B)] [IP packet]
//
// Performance notes:
//   • tcpWriteFrame uses net.Buffers (writev) — single syscall for hdr+payload.
//   • rxLoop reuses a single pre-allocated buffer — zero per-packet allocation.
//   • TCP_NODELAY on every connection — Nagle causes 40 ms latency spikes when
//     the window is small (common for small-MTU tunnel traffic).
//   • 4 MB read/write socket buffers absorb bursts without head-of-line blocking.
//
// WARNING — TCP-over-TCP:
//   Carrying TCP inside TCP is inherently problematic.  When the inner TCP
//   detects loss and retransmits, the outer TCP buffers and retransmits too,
//   creating a cascade that collapses throughput.  For encrypted traffic prefer
//   udp-obfs.  Use this mode only when TCP is the only allowed protocol.
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
)

const tcpSubnet = "10.20.41.0/24"

// TcpTunnel carries IP traffic over a TCP connection.
type TcpTunnel struct {
	cfg    *Config
	tunFd  *os.File
	ln     net.Listener
	connMu sync.Mutex
	conn   net.Conn
	done   chan struct{}
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
		mtu = 1460 // 1500 − 20 (IP) − 20 (TCP)
	}

	header("tcp / " + c.Mode)
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

	addMSS(dev)
	t.done = make(chan struct{})

	tun := t.tunFd // local ref for goroutines (safe vs doClean nil-out)
	go t.txLoop(tun)

	if c.Mode == "server" {
		t.ln, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			return fmt.Errorf("tcp listen :%d: %w", port, err)
		}
		logOK(fmt.Sprintf("TCP listening :%d", port))
		go t.acceptLoop(tun)
	} else {
		go t.connectLoop(tun)
	}

	done(dev, addr, peer,
		fmt.Sprintf("transport : TCP :%d", port),
		"reconnect : automatic (client retries every 3 s)",
		"note      : prefer udp-obfs for better throughput",
		"test      : ping -c3 "+peer,
	)
	return nil
}

// txLoop reads IP packets from TUN and writes framed to current TCP connection.
// One goroutine, pre-allocated buffer — zero per-packet heap allocation.
func (t *TcpTunnel) txLoop(tun *os.File) {
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
		t.connMu.Lock()
		c := t.conn
		t.connMu.Unlock()
		if c == nil {
			continue // no connection yet
		}
		if err := tcpWriteFrame(c, buf[:n]); err != nil {
			logDebug("tcp tx: " + err.Error())
			t.connMu.Lock()
			if t.conn == c {
				_ = t.conn.Close()
				t.conn = nil
			}
			t.connMu.Unlock()
		}
	}
}

// acceptLoop (server): accepts connections, tunes them, starts rx goroutine.
func (t *TcpTunnel) acceptLoop(tun *os.File) {
	for {
		conn, err := t.ln.Accept()
		if err != nil {
			select {
			case <-t.done:
				return
			default:
				logWarn("tcp accept: " + err.Error())
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		tuneTCPConn(conn) // TCP_NODELAY + 4 MB buffers
		logInfo(fmt.Sprintf("tcp: client connected from %s", conn.RemoteAddr()))
		t.connMu.Lock()
		if t.conn != nil {
			_ = t.conn.Close()
		}
		t.conn = conn
		t.connMu.Unlock()
		go t.rxLoop(conn, tun)
	}
}

// connectLoop (client): connects with retry, tunes connection.
func (t *TcpTunnel) connectLoop(tun *os.File) {
	addr := fmt.Sprintf("%s:%d", t.cfg.RemoteIP, t.cfg.Transport.Port)
	for {
		select {
		case <-t.done:
			return
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			logWarn(fmt.Sprintf("tcp connect %s: %v — retry in 3s", addr, err))
			select {
			case <-t.done:
				return
			case <-time.After(3 * time.Second):
				continue
			}
		}
		tuneTCPConn(conn) // TCP_NODELAY + 4 MB buffers
		logOK(fmt.Sprintf("tcp: connected to %s", addr))
		t.connMu.Lock()
		t.conn = conn
		t.connMu.Unlock()
		t.rxLoop(conn, tun) // blocks until connection drops
		t.connMu.Lock()
		if t.conn == conn {
			t.conn = nil
		}
		t.connMu.Unlock()
		select {
		case <-t.done:
			return
		default:
			time.Sleep(time.Second)
		}
	}
}

// rxLoop reads framed IP packets from TCP and writes to TUN.
// Uses a single pre-allocated buffer — zero per-packet heap allocation.
func (t *TcpTunnel) rxLoop(conn net.Conn, tun *os.File) {
	defer conn.Close()
	buf := getBuf()
	defer putBuf(buf)
	var hdr [2]byte
	for {
		select {
		case <-t.done:
			return
		default:
		}
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			select {
			case <-t.done:
			default:
				logDebug("tcp rx: " + err.Error())
			}
			return
		}
		n := int(binary.BigEndian.Uint16(hdr[:]))
		if n == 0 || n > len(buf) {
			logWarn(fmt.Sprintf("tcp rx: invalid frame len %d", n))
			return
		}
		if _, err := io.ReadFull(conn, buf[:n]); err != nil {
			select {
			case <-t.done:
			default:
				logDebug("tcp rx read: " + err.Error())
			}
			return
		}
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

// tcpWriteFrame writes a length-prefixed frame using writev (net.Buffers) —
// a single syscall for header + payload, no intermediate copy.
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
	t.connMu.Lock()
	if t.conn != nil {
		_ = t.conn.Close()
		t.conn = nil
	}
	t.connMu.Unlock()
	if t.tunFd != nil {
		_ = t.tunFd.Close()
		t.tunFd = nil
	}
	delMSS(t.DevName())
	nlDown(t.DevName())
}

func (t *TcpTunnel) Status() {
	if l, err := netlink.LinkByName(t.DevName()); err == nil {
		fmt.Printf("  %s: flags=%v\n", l.Attrs().Name, l.Attrs().Flags)
	}
}
