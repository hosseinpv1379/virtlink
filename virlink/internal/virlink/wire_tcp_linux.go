//go:build linux

package virlink

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func tcpWireControl(_ string, _ string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_FREEBIND, 1)
	})
}

// dialTCPWire connects to real remote_ip:port while binding [mangle] srcip (FREEBIND).
// Outer wire TX: src=srcip, dst=remote_ip — same as ICMP/UDP raw spoof.
func dialTCPWire(cfg *Config, timeout time.Duration) (net.Conn, error) {
	port := cfg.Transport.Port
	if port == 0 {
		port = 8443
	}
	remote := net.JoinHostPort(cfg.RemoteIP, strconv.Itoa(port))

	if !wireSpoofEnabled(cfg) {
		return net.DialTimeout("tcp", remote, timeout)
	}

	w := wireSpoofFrom(cfg)
	logInfo(fmt.Sprintf("[wire] tcp dial: bind src=%s → dst=%s:%d  (expect peer wire src=%s on wire)",
		cfg.Mangle.SrcIP, cfg.RemoteIP, port, cfg.Mangle.DstIP))

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	d := net.Dialer{
		LocalAddr: &net.TCPAddr{IP: net.IP(w.src[:]), Port: 0},
		Control:   tcpWireControl,
	}
	conn, err := d.DialContext(ctx, "tcp", remote)
	if err != nil {
		return nil, err
	}
	if la := conn.LocalAddr(); la != nil {
		logOK(fmt.Sprintf("[wire] tcp connected  local=%s  remote=%s",
			la, conn.RemoteAddr()))
	}
	return conn, nil
}

func listenTCPWire(cfg *Config, port int) (net.Listener, error) {
	if !wireSpoofEnabled(cfg) {
		return net.Listen("tcp", fmt.Sprintf(":%d", port))
	}
	logInfo(fmt.Sprintf("[wire] tcp listen :%d  |  expect client wire src=%s",
		port, cfg.Mangle.DstIP))
	return net.Listen("tcp", fmt.Sprintf(":%d", port))
}
