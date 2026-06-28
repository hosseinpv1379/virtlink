//go:build !linux

package virlink

import (
	"fmt"
	"net"
	"time"
)

func dialTCPWire(cfg *Config, timeout time.Duration) (net.Conn, error) {
	port := cfg.Transport.Port
	if port == 0 {
		port = 8443
	}
	return net.DialTimeout("tcp", fmt.Sprintf("%s:%d", cfg.RemoteIP, port), timeout)
}

func listenTCPWire(cfg *Config, port int) (net.Listener, error) {
	return net.Listen("tcp", fmt.Sprintf(":%d", port))
}
