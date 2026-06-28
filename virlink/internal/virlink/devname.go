// devname.go — Linux interface names derived from tunnel name.
package virlink

import (
	"fmt"
	"strings"
)

const maxIfaceNameLen = 15 // IFNAMSIZ − 1

// sanitizeIfaceName keeps [A-Za-z0-9_-] and truncates to Linux IFNAME limit.
func sanitizeIfaceName(s string) string {
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

// tunnelDevName returns the tunnel's primary interface name.
// Uses [tunnel].name when set; otherwise the type-specific fallback.
func tunnelDevName(c *Config, fallback string) string {
	if c != nil && c.Tunnel.Name != "" {
		return sanitizeIfaceName(c.Tunnel.Name)
	}
	return fallback
}

// tunnelDevNameWithSuffix appends a suffix (e.g. "-w0", "-0") when a tunnel name
// is set; otherwise returns fallback unchanged (legacy gre-mpath0, ovpnm-w0, …).
func tunnelDevNameWithSuffix(c *Config, fallback, suffix string) string {
	if c == nil || c.Tunnel.Name == "" {
		return fallback
	}
	base := sanitizeIfaceName(c.Tunnel.Name)
	maxBase := maxIfaceNameLen - len(suffix)
	if maxBase < 1 {
		maxBase = 1
	}
	if len(base) > maxBase {
		base = base[:maxBase]
	}
	return base + suffix
}

func openvpnMultuWorkerDev(c *Config, i int) string {
	fb := fmt.Sprintf("ovpnm-w%d", i)
	return tunnelDevNameWithSuffix(c, fb, fmt.Sprintf("-w%d", i))
}
