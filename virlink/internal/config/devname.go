// devname.go — Linux interface names derived from tunnel name.
package config

import (
	"fmt"
	"strings"
)

const maxIfaceNameLen = 15 // IFNAMSIZ − 1

// SanitizeIfaceName keeps [A-Za-z0-9_-] and truncates to Linux IFNAME limit.
func SanitizeIfaceName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" {
		return "virlink0"
	}
	if len(out) > maxIfaceNameLen {
		out = out[:maxIfaceNameLen]
	}
	return out
}

// TunnelDevName returns the tunnel's primary interface name.
func TunnelDevName(c *Config, fallback string) string {
	if c != nil && c.Tunnel.Name != "" {
		return SanitizeIfaceName(c.Tunnel.Name)
	}
	return fallback
}

// TunnelDevNameWithSuffix appends a suffix when a tunnel name is set.
func TunnelDevNameWithSuffix(c *Config, fallback, suffix string) string {
	if c == nil || c.Tunnel.Name == "" {
		return fallback
	}
	base := SanitizeIfaceName(c.Tunnel.Name)
	maxBase := maxIfaceNameLen - len(suffix)
	if maxBase < 1 {
		maxBase = 1
	}
	if len(base) > maxBase {
		base = base[:maxBase]
	}
	return base + suffix
}

// OpenvpnMultuWorkerDev returns the dev name for openvpnmultu worker i.
func OpenvpnMultuWorkerDev(c *Config, i int) string {
	fb := fmt.Sprintf("ovpnm-w%d", i)
	return TunnelDevNameWithSuffix(c, fb, fmt.Sprintf("-w%d", i))
}
