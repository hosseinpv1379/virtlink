// mangle_kernel.go — wire IP spoof for kernel tunnels via nftables.
//
// Kernel GRE/IPIP/L2TP/etc. build outer IP headers in-kernel; [mangle] rewrites
// them on output/input hooks. Rules are installed on tunnel up and removed on down.
//
// Wire semantics (same as userspace IPPROTO_RAW / TCP tunnel):
//   TX: outer src = [mangle] srcip, outer dst = real remote_ip (hping3 -a style)
//   RX: peer outer src = peer's srcip (= our dstip) → rewrite to real remote_ip
//       so GRE/TCP stack accepts the packet before demux.
package virlink

import (
	"fmt"
	"os"
	"sync"
)

const (
	nftMangleTable = "virlink_mangle"
	nftFwdTable    = "virlink_fwd"
	mangleMSS      = 1320
	// Run before conntrack (-200) so mangled headers match what the stack tracks.
	nftSpoofPrio = -300
)

var kernelMangleMu sync.Mutex

func isKernelTunnel(typ string) bool {
	switch typ {
	case "gre-fou", "ipip-fou", "bonded-gre-fou", "l2tpv3",
		"gre-fou-ipsec", "gre":
		return true
	default:
		return false
	}
}

func kernelTunnelWireUp(cfg *Config) error {
	if !wireSpoofEnabled(cfg) || !isKernelTunnel(cfg.Tunnel.Type) {
		return nil
	}
	warnWireSpoofPrereqs()
	return applyKernelMangle(cfg)
}

func kernelTunnelWireDown(cfg *Config) {
	if !wireSpoofEnabled(cfg) || !isKernelTunnel(cfg.Tunnel.Type) {
		return
	}
	restoreKernelMangle()
}

func tcpTunnelWireUp(cfg *Config) error {
	if !wireSpoofEnabled(cfg) || (cfg.Tunnel.Type != "tcp" && cfg.Tunnel.Type != "tcpmux") {
		return nil
	}
	warnWireSpoofPrereqs()
	return applyTCPWireMangle(cfg)
}

func tcpTunnelWireDown(cfg *Config) {
	if !wireSpoofEnabled(cfg) || (cfg.Tunnel.Type != "tcp" && cfg.Tunnel.Type != "tcpmux") {
		return
	}
	restoreKernelMangle()
}

// applyKernelMangle installs scoped nftables rules for kernel encapsulation tunnels.
func applyKernelMangle(cfg *Config) error {
	kernelMangleMu.Lock()
	defer kernelMangleMu.Unlock()

	restoreKernelMangleLocked()

	src, peerWireSrc := cfg.Mangle.SrcIP, cfg.Mangle.DstIP
	local, remote := cfg.LocalIP, cfg.RemoteIP
	script := fmt.Sprintf(`table ip %s {
	chain input {
		type filter hook input priority %d; policy accept;
		ip daddr %s ip saddr %s counter name vlk_wire_in_peer ip saddr set %s
	}
	chain output {
		type filter hook output priority %d; policy accept;
		ip daddr %s counter name vlk_wire_out ip saddr set %s
	}
}
table inet %s {
	chain forward {
		type filter hook forward priority filter; policy accept;
		tcp flags syn tcp option maxseg size set %d
	}
}
`, nftMangleTable, nftSpoofPrio, local, peerWireSrc, remote,
		nftSpoofPrio, remote, src, nftFwdTable, mangleMSS)

	if err := nftRunScript(script); err != nil {
		return fmt.Errorf("kernel mangle nft: %w", err)
	}
	initWireMonitor(cfg, wirePathKernel)
	logOK("wire spoof enabled (kernel nftables mangle)")
	logDebug(fmt.Sprintf("wire spoof srcip=%s peer_wire_src=%s mss=%d", src, peerWireSrc, mangleMSS))
	return nil
}

// applyTCPWireMangle rewrites outer TCP IP headers so the tunnel uses spoofed identities.
func applyTCPWireMangle(cfg *Config) error {
	kernelMangleMu.Lock()
	defer kernelMangleMu.Unlock()

	restoreKernelMangleLocked()

	src := cfg.Mangle.SrcIP
	peerWireSrc := cfg.Mangle.DstIP
	local := cfg.LocalIP
	remote := cfg.RemoteIP
	port := cfg.Transport.Port
	if port == 0 {
		port = 8443
	}
	script := fmt.Sprintf(`table ip %s {
	chain prerouting {
		type filter hook prerouting priority %d; policy accept;
		ip daddr %s ip saddr %s tcp sport %d ip saddr set %s counter name vlk_wire_in_peer notrack
		ip daddr %s ip saddr %s tcp dport %d ip saddr set %s counter name vlk_wire_in_peer notrack
	}
	chain output {
		type filter hook output priority %d; policy accept;
		ip daddr %s tcp dport %d ip saddr set %s counter name vlk_wire_out notrack
		ip daddr %s tcp sport %d ip saddr set %s counter name vlk_wire_out notrack
	}
}
table inet %s {
	chain forward {
		type filter hook forward priority filter; policy accept;
		tcp flags syn tcp option maxseg size set %d
	}
}
`, nftMangleTable,
		nftSpoofPrio, local, peerWireSrc, port, remote,
		local, peerWireSrc, port, remote,
		nftSpoofPrio, remote, port, src, remote, port, src,
		nftFwdTable, mangleMSS)

	if err := nftRunScript(script); err != nil {
		return fmt.Errorf("tcp wire mangle nft: %w", err)
	}
	initWireMonitor(cfg, wirePathTCP)
	logOK("wire spoof enabled (TCP nftables mangle)")
	logDebug(fmt.Sprintf("wire spoof srcip=%s peer_wire_src=%s port=%d", src, peerWireSrc, port))
	return nil
}

func restoreKernelMangle() {
	kernelMangleMu.Lock()
	defer kernelMangleMu.Unlock()
	restoreKernelMangleLocked()
}

func restoreKernelMangleLocked() {
	try("nft", "delete", "table", "ip", nftMangleTable)
	try("nft", "delete", "table", "inet", nftFwdTable)
}

func nftRunScript(script string) error {
	f, err := os.CreateTemp("", "virlink-*.nft")
	if err != nil {
		return err
	}
	path := f.Name()
	defer os.Remove(path)

	if _, err := f.WriteString(script); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return run("nft", "-f", path)
}
