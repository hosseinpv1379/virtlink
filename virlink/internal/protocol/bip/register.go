package bip

import (
	"virlink/internal/config"
	"virlink/internal/core"
)

func init() {
	core.Register("bip", core.Meta{
		DefaultMTU: 1480,
		Userspace:  true,
	}, func(cfg *config.Config) (core.Tunnel, error) {
		return &BipTunnel{cfg: cfg}, nil
	})
}
