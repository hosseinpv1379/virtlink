package platform

import "virlink/internal/config"

func TunnelDevName(c *config.Config, fallback string) string {
	return config.TunnelDevName(c, fallback)
}

func TunnelDevNameWithSuffix(c *config.Config, fallback, suffix string) string {
	return config.TunnelDevNameWithSuffix(c, fallback, suffix)
}

func OpenvpnMultuWorkerDev(c *config.Config, i int) string {
	return config.OpenvpnMultuWorkerDev(c, i)
}

func TunnelInstanceName(c *config.Config) string {
	if c.Tunnel.Name != "" {
		return config.SanitizeIfaceName(c.Tunnel.Name)
	}
	return c.Tunnel.Type + "-" + c.Tunnel.Mode
}
