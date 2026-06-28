package virlink

import (
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

	src, peerWireSrc := cfg.Mangle.SrcIP, cfg.Mangle.DstIP
	local, remote := cfg.LocalIP, cfg.RemoteIP
	script := strings.TrimSpace(`table ip ` + nftMangleTable + ` {
	counter vlk_wire_in_peer {}
	counter vlk_wire_out {}
	chain input {
		type filter hook input priority -300; policy accept;
		ip daddr ` + local + ` ip saddr ` + peerWireSrc + ` ip saddr set ` + remote + ` counter name vlk_wire_in_peer
	}
	chain output {
		type filter hook output priority -300; policy accept;
		ip daddr ` + remote + ` ip saddr set ` + src + ` counter name vlk_wire_out
	}
}`)

	if !strings.Contains(script, "counter vlk_wire_in_peer {}") {
		t.Fatal("expected declared nft counter objects")
	}
	if !strings.Contains(script, "ip saddr 37.152.181.38 ip saddr set 64.118.156.193") {
		t.Fatalf("input must rewrite peer wire src to real remote:\n%s", script)
	}
	if !strings.Contains(script, "ip daddr 64.118.156.193") || !strings.Contains(script, "ip saddr set 185.41.1.52") {
		t.Fatalf("output must spoof only source:\n%s", script)
	}
}

func TestTCPWireMangleClientScript(t *testing.T) {
	cfg := &Config{
		Tunnel: TunnelCfg{
			Type:     "tcp",
			Mode:     "client",
			LocalIP:  "95.38.195.35",
			RemoteIP: "64.118.156.193",
		},
		Transport: TransportCfg{Port: 8443},
		Mangle: MangleCfg{
			SrcIP: "185.41.1.52",
			DstIP: "37.152.181.38",
		},
	}
	cfg.LocalIP = cfg.Tunnel.LocalIP
	cfg.RemoteIP = cfg.Tunnel.RemoteIP

	script := tcpWireMangleScript(cfg)
	if !strings.Contains(script, "chain input") || strings.Contains(script, "chain prerouting") {
		t.Fatalf("TCP client must use input hook like GRE, not prerouting:\n%s", script)
	}
	if !strings.Contains(script, "ip saddr 37.152.181.38") || !strings.Contains(script, "ip saddr set 64.118.156.193") {
		t.Fatalf("client input must rewrite WIRE_KHAREJ to REAL_KHAREJ:\n%s", script)
	}
	if !strings.Contains(script, "ip daddr 64.118.156.193 tcp dport 8443") || !strings.Contains(script, "ip saddr set 185.41.1.52") {
		t.Fatalf("client output must spoof wire src on TX:\n%s", script)
	}
}

func TestTCPWireMangleServerScript(t *testing.T) {
	cfg := &Config{
		Tunnel: TunnelCfg{
			Type:     "tcp",
			Mode:     "server",
			LocalIP:  "64.118.156.193",
			RemoteIP: "95.38.195.35",
		},
		Transport: TransportCfg{Port: 8443},
		Mangle: MangleCfg{
			SrcIP: "37.152.181.38",
			DstIP: "185.41.1.52",
		},
	}
	cfg.LocalIP = cfg.Tunnel.LocalIP
	cfg.RemoteIP = cfg.Tunnel.RemoteIP

	script := tcpWireMangleScript(cfg)
	if !strings.Contains(script, "chain input") {
		t.Fatalf("TCP server must use input hook:\n%s", script)
	}
	if !strings.Contains(script, "tcp dport 8443 notrack ip saddr set 95.38.195.35") &&
		!strings.Contains(script, "tcp dport 8443 ip saddr set 95.38.195.35") {
		t.Fatalf("KHAREJ input must rewrite WIRE_IRAN to REAL_IRAN:\n%s", script)
	}
	if !strings.Contains(script, "ip daddr 185.41.1.52 tcp sport 8443") || !strings.Contains(script, "ip saddr set 37.152.181.38") {
		t.Fatalf("KHAREJ output must spoof SRC_KHAREJ on replies:\n%s", script)
	}
}
