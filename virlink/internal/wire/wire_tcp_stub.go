//go:build !linux

package wire

import (
	"virlink/internal/config"
	"fmt"
	"net"
	"time"
)

func DialTCPWire(cfg *config.Config, timeout time.Duration) (net.Conn, error) {
	port := cfg.Transport.Port
	if port == 0 {
		port = 8443
	}
	return net.DialTimeout("tcp", fmt.Sprintf("%s:%d", cfg.RemoteIP, port), timeout)
}

func ListenTCPWire(cfg *config.Config, port int) (net.Listener, error) {
	return net.Listen("tcp", fmt.Sprintf(":%d", port))
}
