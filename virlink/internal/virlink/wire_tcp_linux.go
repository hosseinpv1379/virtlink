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
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TRANSPARENT, 1)
	})
}

// dialTCPWire opens TCP to the peer wire identity ([mangle] dstip) while binding
// [mangle] srcip. A host route (wire dst via real remote_ip) delivers packets to
// the peer without nftables IP mangling.
func dialTCPWire(cfg *Config, timeout time.Duration) (net.Conn, error) {
	port := cfg.Transport.Port
	if port == 0 {
		port = 8443
	}

	if !wireSpoofEnabled(cfg) {
		return net.DialTimeout("tcp", fmt.Sprintf("%s:%d", cfg.RemoteIP, port), timeout)
	}

	w := wireSpoofFrom(cfg)
	remote := net.JoinHostPort(cfg.Mangle.DstIP, strconv.Itoa(port))
	logInfo(fmt.Sprintf("[wire] tcp dial: bind src=%s → wire dst=%s:%d (route via %s)",
		cfg.Mangle.SrcIP, cfg.Mangle.DstIP, port, cfg.RemoteIP))

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

	addr := net.JoinHostPort(cfg.Mangle.SrcIP, strconv.Itoa(port))
	logInfo(fmt.Sprintf("[wire] tcp listen %s  |  expect client wire src=%s",
		addr, cfg.Mangle.DstIP))

	lc := net.ListenConfig{Control: tcpWireControl}
	return lc.Listen(context.Background(), "tcp", addr)
}
