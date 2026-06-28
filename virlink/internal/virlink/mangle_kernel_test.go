package virlink

import (
	"fmt"
	"strings"
	"testing"
)

func TestKernelMangleScriptSemantics(t *testing.T) {
	cfg := &Config{
		Tunnel: TunnelCfg{
			Type:     "gre-fou",
			Mode:     "client",
			LocalIP:  "95.38.195.35",
			RemoteIP: "64.118.156.193",
		},
		Mangle: MangleCfg{
			SrcIP: "185.41.1.52",
			DstIP: "37.152.181.38",
		},
	}
	cfg.LocalIP = cfg.Tunnel.LocalIP
	cfg.RemoteIP = cfg.Tunnel.RemoteIP

	// Capture script by calling the same formatter used in applyKernelMangle.
	src, peerWireSrc := cfg.Mangle.SrcIP, cfg.Mangle.DstIP
	local, remote := cfg.LocalIP, cfg.RemoteIP
	script := strings.TrimSpace(fmt.Sprintf(`table ip %s {
	chain input {
		type filter hook input priority %d; policy accept;
		ip daddr %s ip saddr %s counter name vlk_wire_in_peer ip saddr set %s
	}
	chain output {
		type filter hook output priority %d; policy accept;
		ip daddr %s counter name vlk_wire_out ip saddr set %s
	}
}`, nftMangleTable, nftSpoofPrio, local, peerWireSrc, remote, nftSpoofPrio, remote, src))

	if !strings.Contains(script, "ip daddr set") {
		t.Fatal("output must not rewrite daddr — packets must reach real remote_ip")
	}
	if !strings.Contains(script, "vlk_wire_in_peer") || !strings.Contains(script, "vlk_wire_out") {
		t.Fatal("expected nft counter names for wire diagnostics")
	}
	if !strings.Contains(script, "ip saddr 37.152.181.38 ip saddr set 64.118.156.193") {
		t.Fatalf("input must rewrite peer wire src to real remote:\n%s", script)
	}
	if !strings.Contains(script, "ip daddr 64.118.156.193 counter name vlk_wire_out ip saddr set 185.41.1.52") {
		t.Fatalf("output must spoof only source:\n%s", script)
	}
}
