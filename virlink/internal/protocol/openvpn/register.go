package openvpn

import (
	"virlink/internal/config"
	"virlink/internal/core"
)

func init() {
	core.Register("openvpn", core.Meta{
		DefaultMTU:        1472,
		DefaultPort:       1194,
		Userspace:         true,
		DefaultTuningFast: true,
	}, func(cfg *config.Config) (core.Tunnel, error) {
		return &OpenvpnTunnel{cfg: cfg}, nil
	})
}
