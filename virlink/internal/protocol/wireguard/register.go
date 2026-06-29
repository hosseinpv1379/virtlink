package wireguard

import (
	"virlink/internal/config"
	"virlink/internal/core"
)

func init() {
	core.Register("wireguard", core.Meta{
		DefaultMTU:        1420,
		DefaultPort:       51820,
		Userspace:         true,
		DefaultTuningFast: true,
	}, func(cfg *config.Config) (core.Tunnel, error) {
		return &WireGuardTunnel{cfg: cfg}, nil
	})
}
