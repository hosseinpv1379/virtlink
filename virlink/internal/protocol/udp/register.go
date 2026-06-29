package udp

import (
	"virlink/internal/config"
	"virlink/internal/core"
)

func init() {
	core.Register("udp", core.Meta{
		DefaultMTU:  1472,
		DefaultPort: 5060,
		Userspace:   true,
	}, func(cfg *config.Config) (core.Tunnel, error) {
		return &UdpTunnel{cfg: cfg}, nil
	})
}
