package icmp

import (
	"virlink/internal/config"
	"virlink/internal/core"
)

func init() {
	core.Register("icmp", core.Meta{
		DefaultMTU: 1472,
		Userspace:  true,
	}, func(cfg *config.Config) (core.Tunnel, error) {
		return &IcmpTunnel{cfg: cfg}, nil
	})
}
