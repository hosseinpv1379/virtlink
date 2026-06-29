// validate.go — extended config validation (platform + wire dependencies).
package platform

import (
	"fmt"

	"virlink/internal/config"
	"virlink/internal/core"
	"virlink/internal/wire"
)

// FinalizeConfig applies defaults that depend on platform (health ports).
func FinalizeConfig(c *config.Config) {
	applyHealthPort(c)
	applyHealthHTTPPort(c)
}

// ValidateConfig runs extended validation after config.Load.
func ValidateConfig(c *config.Config) error {
	if err := validateTuningMode(tuningMode(c)); err != nil {
		return err
	}
	if err := validatePerf(&c.Tuning); err != nil {
		return err
	}
	if err := wire.ValidateMangle(&c.Mangle); err != nil {
		return err
	}
	if wire.WireSpoofEnabled(c) {
		if err := wire.ValidateWireSpoofTunnel(c.Tunnel.Type); err != nil {
			return err
		}
	}
	if c.Tunnel.Type == "openvpnmultu" {
		if c.OpenVPNMultu.PKIDir == "" {
			return fmt.Errorf("[openvpnmultu] pki_dir is required")
		}
		if c.OpenVPNMultu.Workers < 2 || c.OpenVPNMultu.Workers > 8 {
			return fmt.Errorf("[openvpnmultu] workers must be 2–8, got %d", c.OpenVPNMultu.Workers)
		}
	}
	if c.Tunnel.Type == "openvpn" {
		if c.OpenVPN.Config == "" {
			return fmt.Errorf("[openvpn] config path is required")
		}
	}
	if c.Tunnel.Type == "hysteria2" {
		if c.Hysteria2.Config == "" {
			return fmt.Errorf("[hysteria2] config path is required")
		}
	}
	if c.Tunnel.Type == "wireguard" {
		if c.WireGuard.Config == "" {
			return fmt.Errorf("[wireguard] config path is required")
		}
	}
	if c.Tunnel.Type == "amneziawg" {
		if c.AmneziaWG.Config == "" {
			return fmt.Errorf("[amneziawg] config path is required")
		}
	}
	_ = core.MetaFor(c.Tunnel.Type) // ensure type registered when protocols linked
	return nil
}
