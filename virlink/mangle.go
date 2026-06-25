// mangle.go — optional nftables source rewrite + forward MSS clamp.
//
// Applied when [mangle] srcip and dstip are both set in config.toml.
// Removed on tunnel teardown. Not exposed via setup.sh.
package main

import (
	"fmt"
	"net"
	"os"
	"sync"
)

const (
	nftMangleTable = "virlink_mangle"
	nftFwdTable    = "virlink_fwd"
	mangleMSS      = 1320
)

var mangleMu sync.Mutex

func mangleEnabled(cfg *Config) bool {
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

// applyMangle installs scoped nftables rules:
//   output: daddr dstip → rewrite source to srcip
//   input:  saddr srcip → rewrite source to dstip
//   forward: TCP SYN MSS clamp (1320)
func applyMangle(cfg *Config) error {
	if !mangleEnabled(cfg) {
		return nil
	}

	mangleMu.Lock()
	defer mangleMu.Unlock()

	restoreMangleLocked()

	src, dst := cfg.Mangle.SrcIP, cfg.Mangle.DstIP
	script := fmt.Sprintf(`table ip %s {
	chain input {
		type filter hook input priority mangle; policy accept;
		ip saddr %s ip saddr set %s
	}
	chain output {
		type filter hook output priority mangle; policy accept;
		ip daddr %s ip saddr set %s
	}
}
table inet %s {
	chain forward {
		type filter hook forward priority filter; policy accept;
		tcp flags syn tcp option maxseg size set %d
	}
}
`, nftMangleTable, src, dst, dst, src, nftFwdTable, mangleMSS)

	if err := nftRunScript(script); err != nil {
		return fmt.Errorf("mangle nft: %w", err)
	}
	logOK("mangle rules applied (restored on teardown)")
	logDebug(fmt.Sprintf("mangle srcip=%s dstip=%s mss=%d", src, dst, mangleMSS))
	return nil
}

func restoreMangle() {
	mangleMu.Lock()
	defer mangleMu.Unlock()
	restoreMangleLocked()
}

func restoreMangleLocked() {
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
