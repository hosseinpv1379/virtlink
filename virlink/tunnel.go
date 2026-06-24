package main

import (
	"fmt"
	"net"
)

// Tunnel manages a virtual link.
type Tunnel interface {
	Up() error        // create kernel objects (netlink), bring interface up
	Down() error      // remove all kernel objects (called on Ctrl+C)
	Status()          // print detailed status to stdout
	DevName() string  // primary interface name (for heartbeat monitoring)
	OverlayIP() string // local overlay IP with prefix, e.g. "10.20.10.1/24"
	PeerIP() string   // peer overlay IP (plain), e.g. "10.20.10.2"
}

// newTunnel creates the appropriate Tunnel implementation for the config.
func newTunnel(cfg *Config) (Tunnel, error) {
	switch cfg.Tunnel.Type {
	case "gre-fou":
		return &GreFouTunnel{cfg: cfg}, nil
	case "ipip-fou":
		return &IpipFouTunnel{cfg: cfg}, nil
	case "bonded-gre-fou":
		return &BondedTunnel{cfg: cfg}, nil
	case "l2tpv3":
		return &L2tpv3Tunnel{cfg: cfg}, nil
	case "gre-wg":
		return &GreWgTunnel{cfg: cfg}, nil
	case "vxlan-wg":
		return &VxlanWgTunnel{cfg: cfg}, nil
	case "gre-fou-ipsec":
		return &IpsecTunnel{cfg: cfg}, nil
	case "udp-obfs":
		return &UdpObfsTunnel{cfg: cfg}, nil
	case "gre":
		return &GreTunnel{cfg: cfg}, nil
	case "tcp":
		return &TcpTunnel{cfg: cfg}, nil
	case "udp":
		return &UdpTunnel{cfg: cfg}, nil
	case "icmp":
		return &IcmpTunnel{cfg: cfg}, nil
	case "bip":
		return &BipTunnel{cfg: cfg}, nil
	}
	return nil, fmt.Errorf("unknown tunnel type: %s", cfg.Tunnel.Type)
}

// ── overlay IP helpers ────────────────────────────────────────────────────────
//
// Priority:
//   1. [tunnel] cidr    — user-defined, e.g. "10.20.10.0/24"
//   2. fallbackSubnet   — per-type default /30
//
// client → base+1,  server → base+2

func overlayAddr(cfg *Config, fallback string) string {
	subnet := cfg.Tunnel.CIDR
	if subnet == "" {
		subnet = fallback
	}
	return computeOverlay(cfg.Mode, subnet)
}

func peerAddr(cfg *Config, fallback string) string {
	subnet := cfg.Tunnel.CIDR
	if subnet == "" {
		subnet = fallback
	}
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return ""
	}
	ones, _ := ipNet.Mask.Size()
	ip := make(net.IP, 4)
	copy(ip, ipNet.IP.To4())
	if cfg.Mode == "client" {
		ip[3] = 2
	} else {
		ip[3] = 1
	}
	_ = ones
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

// plainIP strips /prefix from a CIDR string.
func plainIP(cidr string) string {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return cidr
	}
	return ip.String()
}
