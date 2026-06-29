package kernel

import (
	"virlink/internal/config"
	"virlink/internal/core"
)

func init() {
	registerKernel("gre-fou", core.Meta{DefaultMTU: 1420, DefaultPort: 5556, Kernel: true},
		func(cfg *config.Config) (core.Tunnel, error) { return &GreFouTunnel{cfg: cfg}, nil })
	registerKernel("ipip-fou", core.Meta{DefaultMTU: 1440, DefaultPort: 5055, Kernel: true},
		func(cfg *config.Config) (core.Tunnel, error) { return &IpipFouTunnel{cfg: cfg}, nil })
	registerKernel("bonded-gre-fou", core.Meta{DefaultMTU: 1400, DefaultPort: 5557, DefaultPort2Delta: 1, Kernel: true},
		func(cfg *config.Config) (core.Tunnel, error) { return &BondedTunnel{cfg: cfg}, nil })
	registerKernel("l2tpv3", core.Meta{DefaultMTU: 1464, DefaultPort: 5059, Kernel: true},
		func(cfg *config.Config) (core.Tunnel, error) { return &L2tpv3Tunnel{cfg: cfg}, nil })
	registerKernel("gre-fou-ipsec", core.Meta{DefaultMTU: 1380, DefaultPort: 5556, Kernel: true},
		func(cfg *config.Config) (core.Tunnel, error) { return &IpsecTunnel{cfg: cfg}, nil })
	registerKernel("gre", core.Meta{DefaultMTU: 1476, Kernel: true},
		func(cfg *config.Config) (core.Tunnel, error) { return &GreTunnel{cfg: cfg}, nil })
}

func registerKernel(name string, meta core.Meta, factory core.Factory) {
	core.Register(name, meta, factory)
}
