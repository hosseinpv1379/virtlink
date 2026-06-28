// mangle_kernel.go — stateless wire IP relay via nftables.
//
// Roles: client = near side (IRAN), server = far side (KHAREJ) in typical deploy.
// [mangle] srcip = our wire identity (SRC_IRAN / SRC_KHAREJ on the wire).
// [mangle] dstip = peer wire identity we accept on RX (WIRE_KHAREJ / WIRE_IRAN).
// remote_ip   = real routable peer (REAL_KHAREJ / REAL_IRAN) for stack + routing.
//
// Relay (same for kernel GRE and TCP):
//   TX output:  daddr real peer → saddr our wire src
//   RX input:   saddr peer wire → saddr real peer (stack sees real IP)
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
	if err := applyTCPWireMangle(cfg); err != nil {
		tcpWireKernelDown(cfg)
		return err
	}
	initWireMonitor(cfg, wirePathTCP)
	logOK("wire relay enabled (TCP: stack real IP + nft input/output like GRE)")
	logWireRelayRoles(cfg)
	return nil
}

func tcpTunnelWireDown(cfg *Config) {
	if !wireSpoofEnabled(cfg) || (cfg.Tunnel.Type != "tcp" && cfg.Tunnel.Type != "tcpmux") {
		return
	}
	tcpWireKernelDown(cfg)
	restoreTCPWireMangle()
}

// applyKernelMangle installs scoped nftables rules for kernel encapsulation tunnels.
func applyKernelMangle(cfg *Config) error {
	kernelMangleMu.Lock()
	defer kernelMangleMu.Unlock()

	restoreKernelMangleLocked()

	src, peerWireSrc := cfg.Mangle.SrcIP, cfg.Mangle.DstIP
	local, remote := cfg.LocalIP, cfg.RemoteIP
	script := fmt.Sprintf(`table ip %s {
	counter vlk_wire_in_peer {}
	counter vlk_wire_out {}
	chain input {
		type filter hook input priority %d; policy accept;
		ip daddr %s ip saddr %s ip saddr set %s counter name vlk_wire_in_peer
	}
	chain output {
		type filter hook output priority %d; policy accept;
		ip daddr %s ip saddr set %s counter name vlk_wire_out
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
	logOK("wire relay enabled (kernel nft mangle)")
	logWireRelayRoles(cfg)
	return nil
}

// applyTCPWireMangle — stateless TCP wire relay (IRAN client / KHAREJ server).
func applyTCPWireMangle(cfg *Config) error {
	kernelMangleMu.Lock()
	defer kernelMangleMu.Unlock()

	restoreTCPWireMangleLocked()

	script := tcpWireMangleScript(cfg)
	if err := nftRunScript(script); err != nil {
		return fmt.Errorf("tcp wire mangle nft: %w", err)
	}
	logWireNFTStatus()
	return nil
}

func tcpWireMangleScript(cfg *Config) string {
	wireSrc := cfg.Mangle.SrcIP
	peerWire := cfg.Mangle.DstIP
	localReal := cfg.LocalIP
	peerReal := cfg.RemoteIP
	port := cfg.Transport.Port
	if port == 0 {
		port = 8443
	}

	role := "KHAREJ"
	if cfg.Mode == "client" {
		role = "IRAN"
	}

	var input, output string
	if cfg.Mode == "client" {
		// IRAN: input RX wire→real; output TX real dst→wire src (same hooks as GRE)
		input = fmt.Sprintf(`# IRAN RX: WIRE_KHAREJ → REAL_KHAREJ
		ip daddr %s ip saddr %s tcp sport %d ip saddr set %s counter name vlk_wire_in_peer`,
			localReal, peerWire, port, peerReal)
		output = fmt.Sprintf(`# IRAN TX: daddr REAL_KHAREJ → src SRC_IRAN
		ip daddr %s tcp dport %d ip saddr set %s counter name vlk_wire_out`,
			peerReal, port, wireSrc)
	} else {
		input = fmt.Sprintf(`# KHAREJ RX: WIRE_IRAN → REAL_IRAN
		ip daddr %s ip saddr %s tcp dport %d ip saddr set %s counter name vlk_wire_in_peer`,
			localReal, peerWire, port, peerReal)
		output = fmt.Sprintf(`# KHAREJ TX: daddr WIRE_IRAN → src SRC_KHAREJ
		ip daddr %s tcp sport %d ip saddr set %s counter name vlk_wire_out
		ip daddr %s tcp sport %d ip saddr set %s counter name vlk_wire_out`,
			peerWire, port, wireSrc,
			peerReal, port, wireSrc)
	}

	return fmt.Sprintf(`# virlink wire relay (%s) wire_src=%s peer_wire=%s real_peer=%s port=%d
table ip %s {
	counter vlk_wire_in_peer {}
	counter vlk_wire_out {}
	chain input {
		type filter hook input priority %d; policy accept;
		%s
	}
	chain output {
		type filter hook output priority %d; policy accept;
		%s
	}
}
table inet %s {
	chain forward {
		type filter hook forward priority filter; policy accept;
		tcp flags syn tcp option maxseg size set %d
	}
}
`, role, wireSrc, peerWire, peerReal, port,
		nftMangleTable, nftSpoofPrio, input, nftSpoofPrio, output, nftFwdTable, mangleMSS)
}

func logWireRelayRoles(cfg *Config) {
	wireSrc := cfg.Mangle.SrcIP
	peerWire := cfg.Mangle.DstIP
	peerReal := cfg.RemoteIP
	if cfg.Mode == "client" {
		logInfo(fmt.Sprintf("[wire] IRAN  TX src %s → dst %s  |  RX wire %s → stack %s",
			wireSrc, peerReal, peerWire, peerReal))
	} else {
		logInfo(fmt.Sprintf("[wire] KHAREJ TX src %s → dst %s  |  RX wire %s → stack %s",
			wireSrc, peerWire, peerWire, peerReal))
	}
	logDebug(fmt.Sprintf("[wire] relay MSS=%d  nft table ip %s", mangleMSS, nftMangleTable))
}

func restoreTCPWireMangle() {
	kernelMangleMu.Lock()
	defer kernelMangleMu.Unlock()
	restoreTCPWireMangleLocked()
}

func restoreTCPWireMangleLocked() {
	try("nft", "delete", "table", "ip", nftMangleTable)
	restoreTCPMSSForwardLocked()
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
