// spoof.go — optional wire IP spoofing ([mangle] srcip / dstip).
//
// Userspace tunnels (icmp/udp/bip): IPPROTO_RAW in-process.
// TX outer IP: src=srcip, dst=real remote_ip (like hping3 -a).
// RX accept: outer src = peer's srcip (= our mangle dstip).
package wire

import (
	"virlink/internal/config"
	"fmt"
	"net"
	"sync/atomic"
)

const ipHdrLen = 20

type WireSpoof struct {
	On  bool
	src [4]byte
	dst [4]byte
}

func WireSpoofFrom(cfg *config.Config) WireSpoof {
	if cfg.Mangle.SrcIP == "" && cfg.Mangle.DstIP == "" {
		return WireSpoof{}
	}
	return WireSpoof{
		On:  true,
		src: ipTo4(cfg.Mangle.SrcIP),
		dst: ipTo4(cfg.Mangle.DstIP),
	}
}

func WireSpoofEnabled(cfg *config.Config) bool {
	return cfg.Mangle.SrcIP != "" && cfg.Mangle.DstIP != ""
}

func ValidateMangle(m *config.MangleCfg) error {
	if m.SrcIP == "" && m.DstIP == "" {
		return nil
	}
	if m.SrcIP == "" || m.DstIP == "" {
		return fmt.Errorf("[mangle] srcip and dstip must both be set (or omit both)")
	}
	if net.ParseIP(m.SrcIP) == nil || net.ParseIP(m.SrcIP).To4() == nil {
		return fmt.Errorf("[mangle] srcip %q is not a valid IPv4 address", m.SrcIP)
	}
	if net.ParseIP(m.DstIP) == nil || net.ParseIP(m.DstIP).To4() == nil {
		return fmt.Errorf("[mangle] dstip %q is not a valid IPv4 address", m.DstIP)
	}
	if m.SrcIP == m.DstIP {
		return fmt.Errorf("[mangle] srcip and dstip must be different")
	}
	return nil
}

func ValidateWireSpoofTunnel(typ string) error {
	switch typ {
	case "icmp", "udp", "bip", "tcp", "tcpmux",
		"gre", "gre-fou", "ipip-fou", "bonded-gre-fou", "l2tpv3", "gre-fou-ipsec":
		return nil
	case "udp-obfs":
		return fmt.Errorf("[mangle] wire spoof is not supported for %q tunnel", typ)
	case "openvpn", "openvpnmultu", "hysteria2", "wireguard", "amneziawg":
		return fmt.Errorf("[mangle] wire spoof is not supported for %q tunnel", typ)
	default:
		return fmt.Errorf("[mangle] wire spoof is not supported for %q tunnel", typ)
	}
}

// WireSpoofTunnelTypes lists tunnel types that support [mangle] wire relay.
func WireSpoofTunnelTypes() []string {
	return []string{
		"icmp", "udp", "bip", "tcp", "tcpmux",
		"gre", "gre-fou", "ipip-fou", "bonded-gre-fou", "l2tpv3", "gre-fou-ipsec",
	}
}

// wirePeer is the outer source IP we accept from the peer on RX (= peer's mangle srcip).
func (w WireSpoof) wirePeer(fallback [4]byte) [4]byte {
	if w.On {
		return w.dst
	}
	return fallback
}

// rememberPeerRoute returns the real routable peer IP for sendto.
// With wire spoof, recvfrom reports the spoofed outer src — not usable for routing.
func RememberPeerRoute(w WireSpoof, fromAddr, configuredPeer [4]byte) [4]byte {
	if w.On {
		return configuredPeer
	}
	return fromAddr
}

func LogWireSpoof(cfg *config.Config, w WireSpoof) {
	if !w.On {
		return
	}
	initWireMonitor(cfg, wirePathUserspace)
	wireLogOK("wire spoof enabled (IPPROTO_RAW)")
	wireLogDebug(fmt.Sprintf("wire spoof srcip=%v dstip=%v", w.src, w.dst))
}

func WarnWireSpoofPrereqs() {
	wireLogWarn("wire spoof: require root + rp_filter=0 (sysctl net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0)")
}

func WireTCPDoneExtra(cfg *config.Config) string {
	if !WireSpoofEnabled(cfg) {
		return ""
	}
	return fmt.Sprintf("wire      : IRAN/KHAREJ relay  TX src=%s dst=%s  RX wire %s→%s",
		cfg.Mangle.SrcIP, cfg.RemoteIP, cfg.Mangle.DstIP, cfg.RemoteIP)
}

var wireTxErrWarned atomic.Bool

func NoteWireTxErr(n int) {
	if n <= 0 {
		return
	}
	if wireTxErrWarned.CompareAndSwap(false, true) {
		wireLogWarn(fmt.Sprintf("[wire] TX failed %d packet(s) — run as root, rp_filter=0, check firewall / routing", n))
	} else if n > 0 {
		wireLogDebug(fmt.Sprintf("[wire] TX failed %d packet(s)", n))
	}
}
