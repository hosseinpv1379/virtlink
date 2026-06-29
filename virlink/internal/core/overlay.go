package core

import (
	"fmt"
	"net"

	"virlink/internal/config"
)

// OverlayAddr returns local overlay CIDR (client → .1, server → .2).
func OverlayAddr(cfg *config.Config, fallback string) string {
	subnet := cfg.Tunnel.CIDR
	if subnet == "" {
		subnet = fallback
	}
	return computeOverlay(cfg.Mode, subnet)
}

// PeerAddr returns peer overlay IP without prefix.
func PeerAddr(cfg *config.Config, fallback string) string {
	subnet := cfg.Tunnel.CIDR
	if subnet == "" {
		subnet = fallback
	}
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return ""
	}
	ip := make(net.IP, 4)
	copy(ip, ipNet.IP.To4())
	if cfg.Mode == "client" {
		ip[3] = 2
	} else {
		ip[3] = 1
	}
	return ip.String()
}

// PlainIP strips /prefix from a CIDR string.
func PlainIP(cidr string) string {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return cidr
	}
	return ip.String()
}

func computeOverlay(mode, subnet string) string {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return subnet
	}
	ones, _ := ipNet.Mask.Size()
	ip := make(net.IP, 4)
	copy(ip, ipNet.IP.To4())
	if mode == "client" {
		ip[3] = 1
	} else {
		ip[3] = 2
	}
	return fmt.Sprintf("%s/%d", ip.String(), ones)
}
