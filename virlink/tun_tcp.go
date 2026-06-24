// tun_tcp.go — TCP tunnel.
//
// Architecture:
//   [TUN device] ←→ [Go userspace] ←→ [TCP socket]
//
// A TUN interface is created in the kernel.
// IP packets from the TUN device are framed (2-byte big-endian length prefix)
// and sent over a TCP connection to the peer.
//
// Framing: [uint16 length (2B)] [IP packet]
//
// Server: listens on :port, accepts one connection at a time.
// Client: connects to remote:port with automatic reconnection (3s backoff).
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
	ln     net.Listener // server only
	connMu sync.Mutex
	conn   net.Conn    // current active TCP connection
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

	// single tx goroutine: reads TUN, writes to current TCP conn
	go t.txLoop()

	if c.Mode == "server" {
		t.ln, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			return fmt.Errorf("tcp listen :%d: %w", port, err)
		}
		logOK(fmt.Sprintf("TCP listening :%d", port))
		go t.acceptLoop()
	} else {
		go t.connectLoop()
	}

	done(dev, addr, peer,
		fmt.Sprintf("transport : TCP :%d  (length-prefixed framing)", port),
		"reconnect : automatic (client retries every 3 s)",
		"test      : ping -c3 "+peer,
	)
	return nil
}

// txLoop reads IP packets from TUN and writes them to the current TCP connection.
// Runs for the entire lifetime of the tunnel.
func (t *TcpTunnel) txLoop() {
	buf := make([]byte, 65536)
	for {
		n, err := t.tunFd.Read(buf)
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
				t.conn.Close()
				t.conn = nil
			}
			t.connMu.Unlock()
		}
	}
}

// acceptLoop (server): accepts TCP connections and starts an rx goroutine per connection.
func (t *TcpTunnel) acceptLoop() {
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
		logInfo(fmt.Sprintf("tcp: client connected from %s", conn.RemoteAddr()))
		t.connMu.Lock()
		if t.conn != nil {
			t.conn.Close()
		}
		t.conn = conn
		t.connMu.Unlock()
		go t.rxLoop(conn)
	}
}

// connectLoop (client): connects to server and reconnects on failure.
func (t *TcpTunnel) connectLoop() {
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
		logOK(fmt.Sprintf("tcp: connected to %s", addr))
		t.connMu.Lock()
		t.conn = conn
		t.connMu.Unlock()
		t.rxLoop(conn) // blocks until connection drops
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

// rxLoop reads framed IP packets from TCP and writes them to TUN.
func (t *TcpTunnel) rxLoop(conn net.Conn) {
	defer conn.Close()
	for {
		pkt, err := tcpReadFrame(conn)
		if err != nil {
			select {
			case <-t.done:
				return
			default:
				logDebug("tcp rx: " + err.Error())
				return
			}
		}
		if _, err := t.tunFd.Write(pkt); err != nil {
			select {
			case <-t.done:
				return
			default:
				logWarn("tun write: " + err.Error())
			}
		}
	}
}

// tcpWriteFrame writes a length-prefixed frame: [uint16][payload].
func tcpWriteFrame(conn net.Conn, data []byte) error {
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(data)))
	// Write header + payload as two separate writes — no extra alloc
	if _, err := conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err := conn.Write(data)
	return err
}

// tcpReadFrame reads a length-prefixed frame from TCP.
func tcpReadFrame(conn net.Conn) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 || n > 65535 {
		return nil, fmt.Errorf("invalid frame length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
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
		t.ln.Close()
		t.ln = nil
	}
	t.connMu.Lock()
	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
	}
	t.connMu.Unlock()
	if t.tunFd != nil {
		t.tunFd.Close()
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
