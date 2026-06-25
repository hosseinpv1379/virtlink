// mangle_kernel.go — wire IP spoof for kernel tunnels via nftables.
//
// Kernel GRE/IPIP/L2TP/etc. build outer IP headers in-kernel; [mangle] rewrites
// them on output/input hooks. Rules are installed on tunnel up and removed on down.
package main

import (
	"fmt"
	"os"
	"sync"
)

const (
	nftMangleTable = "virlink_mangle"
	nftFwdTable    = "virlink_fwd"
	mangleMSS      = 1320
)

var kernelMangleMu sync.Mutex

func isKernelTunnel(typ string) bool {
	switch typ {
	case "gre-fou", "ipip-fou", "bonded-gre-fou", "l2tpv3",
		"gre-wg", "vxlan-wg", "gre-fou-ipsec", "gre":
		return true
	default:
		return false
	}
}

func kernelTunnelWireUp(cfg *Config) error {
	if !wireSpoofEnabled(cfg) || !isKernelTunnel(cfg.Tunnel.Type) {
		return nil
	}
	return applyKernelMangle(cfg)
}

func kernelTunnelWireDown(cfg *Config) {
	if !wireSpoofEnabled(cfg) || !isKernelTunnel(cfg.Tunnel.Type) {
		return
	}
	restoreKernelMangle()
}

// applyKernelMangle installs scoped nftables rules:
//   output: daddr dstip → rewrite source to srcip
//   input:  saddr srcip → rewrite source to dstip
//   forward: TCP SYN MSS clamp (1320)
func applyKernelMangle(cfg *Config) error {
	kernelMangleMu.Lock()
	defer kernelMangleMu.Unlock()

	restoreKernelMangleLocked()

	src, dst := cfg.Mangle.SrcIP, cfg.Mangle.DstIP
	remote := cfg.RemoteIP
	script := fmt.Sprintf(`table ip %s {
	chain input {
		type filter hook input priority mangle; policy accept;
		ip saddr %s ip saddr set %s
	}
	chain output {
		type filter hook output priority mangle; policy accept;
		ip daddr %s ip saddr set %s ip daddr set %s
	}
}
table inet %s {
	chain forward {
		type filter hook forward priority filter; policy accept;
		tcp flags syn tcp option maxseg size set %d
	}
}
`, nftMangleTable, src, dst, remote, src, dst, nftFwdTable, mangleMSS)

	if err := nftRunScript(script); err != nil {
		return fmt.Errorf("kernel mangle nft: %w", err)
	}
	logOK("wire spoof enabled (kernel nftables mangle)")
	logDebug(fmt.Sprintf("wire spoof srcip=%s dstip=%s mss=%d", src, dst, mangleMSS))
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
