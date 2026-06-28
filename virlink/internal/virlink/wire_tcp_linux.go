//go:build linux

package virlink

import (
	"fmt"
	"net"
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

// dialTCPWire opens a TCP stream to the real remote_ip:port while binding the
// socket to [mangle] srcip. nftables prerouting rewrites the peer's wire src
// on replies so the kernel stack matches this dial().
func dialTCPWire(cfg *Config, timeout time.Duration) (net.Conn, error) {
	port := cfg.Transport.Port
	if port == 0 {
		port = 8443
	}
	remote := fmt.Sprintf("%s:%d", cfg.RemoteIP, port)

	if !wireSpoofEnabled(cfg) {
		return net.DialTimeout("tcp", remote, timeout)
	}

	w := wireSpoofFrom(cfg)
	logInfo(fmt.Sprintf("[wire] tcp dial: bind src=%s → route dst=%s:%d  |  wire TX src=%s  |  expect reply outer src=%s (nft→%s)",
		cfg.Mangle.SrcIP, cfg.RemoteIP, port,
		cfg.Mangle.SrcIP, cfg.Mangle.DstIP, cfg.RemoteIP))

	d := net.Dialer{
		Timeout:   timeout,
		LocalAddr: &net.TCPAddr{IP: net.IP(w.src[:]), Port: 0},
		Control:   tcpWireControl,
	}
	conn, err := d.Dial("tcp", remote)
	if err != nil {
		return nil, err
	}
	if la := conn.LocalAddr(); la != nil {
		logOK(fmt.Sprintf("[wire] tcp connected  local=%s  remote=%s  (overlay traffic uses this stream)",
			la, conn.RemoteAddr()))
	}
	return conn, nil
}

func listenTCPWire(cfg *Config, port int) (net.Listener, error) {
	if !wireSpoofEnabled(cfg) {
		return net.Listen("tcp", fmt.Sprintf(":%d", port))
	}
	logInfo(fmt.Sprintf("[wire] tcp listen :%d  |  accept wire src=%s → stack sees real client  |  reply wire src=%s",
		port, cfg.Mangle.DstIP, cfg.Mangle.SrcIP))
	return net.Listen("tcp", fmt.Sprintf(":%d", port))
}
