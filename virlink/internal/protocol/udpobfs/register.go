package udpobfs

import (
	"virlink/internal/config"
	"virlink/internal/core"
)

func init() {
	core.Register("udp-obfs", core.Meta{
		DefaultMTU:  1400,
		DefaultPort: 443,
		Userspace:   true,
	}, func(cfg *config.Config) (core.Tunnel, error) {
		return &UdpObfsTunnel{cfg: cfg}, nil
	})
}
