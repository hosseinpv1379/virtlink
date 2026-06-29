package tcpmux

import (
	"virlink/internal/config"
	"virlink/internal/core"
)

func init() {
	core.Register("tcpmux", core.Meta{
		DefaultMTU:   1460,
		DefaultPort:  8443,
		Userspace:    true,
		TcpUserspace: true,
	}, func(cfg *config.Config) (core.Tunnel, error) {
		return &TcpMuxTunnel{cfg: cfg}, nil
	})
}
