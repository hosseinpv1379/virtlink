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
	if err := tcpWireKernelUp(cfg); err != nil {
		return err
	}
	if err := applyTCPMSSForward(); err != nil {
		tcpWireKernelDown(cfg)
		return err
	}
	initWireMonitor(cfg, wirePathTCPSock)
	logOK("wire spoof enabled (TCP kernel socket: FREEBIND bind src, dial real remote)")
	logDebug(fmt.Sprintf("wire spoof srcip=%s peer_wire=%s", cfg.Mangle.SrcIP, cfg.Mangle.DstIP))
	return nil
}

func tcpTunnelWireDown(cfg *Config) {
	if !wireSpoofEnabled(cfg) || (cfg.Tunnel.Type != "tcp" && cfg.Tunnel.Type != "tcpmux") {
		return
	}
	tcpWireKernelDown(cfg)
	restoreTCPMSSForward()
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

// applyTCPMSSForward clamps MSS on forwarded overlay traffic (no IP mangling).
func applyTCPMSSForward() error {
	kernelMangleMu.Lock()
	defer kernelMangleMu.Unlock()

	restoreTCPMSSForwardLocked()

	script := fmt.Sprintf(`table inet %s {
	chain forward {
		type filter hook forward priority filter; policy accept;
		tcp flags syn tcp option maxseg size set %d
	}
}
`, nftFwdTable, mangleMSS)

	if err := nftRunScript(script); err != nil {
		return fmt.Errorf("tcp mss nft: %w", err)
	}
	return nil
}

func restoreTCPMSSForward() {
	kernelMangleMu.Lock()
	defer kernelMangleMu.Unlock()
	restoreTCPMSSForwardLocked()
}

func restoreTCPMSSForwardLocked() {
	try("nft", "delete", "table", "inet", nftFwdTable)
}

func restoreKernelMangle() {
	kernelMangleMu.Lock()
	defer kernelMangleMu.Unlock()
	restoreKernelMangleLocked()
}

func restoreKernelMangleLocked() {
	try("nft", "delete", "table", "ip", nftMangleTable)
	restoreTCPMSSForwardLocked()
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
