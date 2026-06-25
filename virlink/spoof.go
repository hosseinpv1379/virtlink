// spoof.go — optional wire IP spoofing ([mangle] srcip / dstip).
//
// Userspace tunnels (icmp/udp/bip): IPPROTO_RAW in-process.
// TX outer IP: src=srcip, dst=real remote_ip (like hping3 -a).
// RX accept: outer src = peer's srcip (= our mangle dstip).
package main

import (
	"fmt"
	"net"
	"sync/atomic"
)

const ipHdrLen = 20

type wireSpoof struct {
	on  bool
	src [4]byte
	dst [4]byte
}

func wireSpoofFrom(cfg *Config) wireSpoof {
	if cfg.Mangle.SrcIP == "" && cfg.Mangle.DstIP == "" {
		return wireSpoof{}
	}
	return wireSpoof{
		on:  true,
		src: ipTo4(cfg.Mangle.SrcIP),
		dst: ipTo4(cfg.Mangle.DstIP),
	}
}

func wireSpoofEnabled(cfg *Config) bool {
	return cfg.Mangle.SrcIP != "" && cfg.Mangle.DstIP != ""
}

func validateMangle(m *MangleCfg) error {
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

func validateWireSpoofTunnel(typ string) error {
	switch typ {
	case "tcp", "udp-obfs":
		return fmt.Errorf("[mangle] wire spoof is not supported for %q tunnel", typ)
	default:
		return nil
	}
}

// wirePeer is the outer source IP we accept from the peer on RX (= peer's mangle srcip).
func (w wireSpoof) wirePeer(fallback [4]byte) [4]byte {
	if w.on {
		return w.dst
	}
	return fallback
}

// rememberPeerRoute returns the real routable peer IP for sendto.
// With wire spoof, recvfrom reports the spoofed outer src — not usable for routing.
func rememberPeerRoute(w wireSpoof, fromAddr, configuredPeer [4]byte) [4]byte {
	if w.on {
		return configuredPeer
	}
	return fromAddr
}

func logWireSpoof(w wireSpoof) {
	if !w.on {
		return
	}
	logOK("wire spoof enabled (IPPROTO_RAW)")
	logDebug(fmt.Sprintf("wire spoof srcip=%v dstip=%v", w.src, w.dst))
}

var wireTxErrWarned atomic.Bool

func noteWireTxErr(n int) {
	if n <= 0 {
		return
	}
	if wireTxErrWarned.CompareAndSwap(false, true) {
		logWarn(fmt.Sprintf("wire tx: %d packet(s) failed — run as root, set rp_filter=0, check firewall", n))
	}
}
