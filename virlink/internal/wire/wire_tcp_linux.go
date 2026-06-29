//go:build linux

package wire

import (
	"virlink/internal/config"
	"context"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func tcpWireReuseControl(_ string, _ string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	})
}

// dialTCPWire connects to REAL peer; nft output rewrites outer src to [mangle] srcip
// (same relay model as kernel GRE — stack uses real IPs, wire sees spoof).
func DialTCPWire(cfg *config.Config, timeout time.Duration) (net.Conn, error) {
	port := cfg.Transport.Port
	if port == 0 {
		port = 8443
	}
	remote := net.JoinHostPort(cfg.RemoteIP, strconv.Itoa(port))

	if !WireSpoofEnabled(cfg) {
		return net.DialTimeout("tcp4", remote, timeout)
	}

	logInfo(fmt.Sprintf("[wire] tcp dial: stack %s → %s:%d  |  nft TX src→%s  RX wire %s→%s",
		cfg.LocalIP, cfg.RemoteIP, port, cfg.Mangle.SrcIP, cfg.Mangle.DstIP, cfg.RemoteIP))

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	localIP := net.ParseIP(cfg.LocalIP)
	d := net.Dialer{
		LocalAddr: &net.TCPAddr{IP: localIP, Port: 0},
		Control:   tcpWireReuseControl,
	}
	conn, err := d.DialContext(ctx, "tcp4", remote)
	if err != nil {
		return nil, err
	}
	wireLogOK(fmt.Sprintf("[wire] tcp connected  local=%s  remote=%s", conn.LocalAddr(), conn.RemoteAddr()))
	return conn, nil
}

func ListenTCPWire(cfg *config.Config, port int) (net.Listener, error) {
	if !WireSpoofEnabled(cfg) {
		return net.Listen("tcp4", fmt.Sprintf(":%d", port))
	}
	bind := net.JoinHostPort(cfg.LocalIP, strconv.Itoa(port))
	logInfo(fmt.Sprintf("[wire] tcp listen %s  |  RX wire src=%s → stack %s",
		bind, cfg.Mangle.DstIP, cfg.RemoteIP))

	lc := net.ListenConfig{Control: tcpWireReuseControl}
	return lc.Listen(context.Background(), "tcp4", bind)
}
