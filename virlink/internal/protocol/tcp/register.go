package tcp

import (
	"virlink/internal/config"
	"virlink/internal/core"
)

func init() {
	core.Register("tcp", core.Meta{
		DefaultMTU:   1460,
		DefaultPort:  8443,
		Userspace:    true,
		TcpUserspace: true,
	}, func(cfg *config.Config) (core.Tunnel, error) {
		return &TcpTunnel{cfg: cfg}, nil
	})
}
