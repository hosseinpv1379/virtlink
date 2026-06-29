package hysteria2

import (
	"virlink/internal/config"
	"virlink/internal/core"
)

func init() {
	core.Register("hysteria2", core.Meta{
		DefaultMTU:        1400,
		DefaultPort:       443,
		Userspace:         true,
		DefaultTuningFast: true,
		DisableHealth:     true,
	}, func(cfg *config.Config) (core.Tunnel, error) {
		return &Hysteria2Tunnel{cfg: cfg}, nil
	})
}
