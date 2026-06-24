// setup.go — system-level preparation.
// sysctl  → /proc/sys/ (native, no subprocess)
// modules → modprobe  (kernel has no user-API for this)
// iptables → iptables binary (MSS clamping rules)
package main

import (
	"fmt"
)

// applySysctl applies all required kernel parameters directly via /proc/sys/.
func applySysctl() {
	params := []struct{ k, v string }{
		{"net.ipv4.ip_forward", "1"},
		{"net.ipv6.conf.all.forwarding", "1"},
		{"net.core.default_qdisc", "fq"},
		{"net.ipv4.tcp_congestion_control", "bbr"},
		{"net.ipv4.tcp_rmem", "4096 1048576 134217728"},
		{"net.ipv4.tcp_wmem", "4096 1048576 134217728"},
		{"net.ipv4.tcp_mtu_probing", "1"},
	}
	for _, p := range params {
		if err := nlSysctl(p.k, p.v); err != nil {
			warn(fmt.Sprintf("sysctl %s: %v", p.k, err))
		}
	}
	logOK("sysctl applied (via /proc/sys)")
}

// loadModules loads kernel modules via modprobe.
// Failures are warnings — the module may be compiled into the kernel.
func loadModules(modules ...string) {
	for _, m := range modules {
		if err := run("modprobe", m); err != nil {
			warn(fmt.Sprintf("modprobe %s: %v (may be built-in)", m, err))
		} else {
			logOK("module " + m)
		}
	}
}

// setupBonding writes max_bonds=0 before loading the bonding module.
// Without this, modprobe bonding auto-creates bond0 which steals the
// primary interface's MAC → SSH disconnects.
func setupBonding() error {
	const confPath = "/etc/modprobe.d/bonding.conf"
	if err := nlSysctl("", ""); err != nil { // ensure /proc is writeable
		_ = err
	}
	if err := run("sh", "-c",
		"echo 'options bonding max_bonds=0' > "+confPath); err != nil {
		return fmt.Errorf("write bonding.conf: %w", err)
	}
	logOK("bonding.conf: max_bonds=0")
	loadModules("bonding")
	return nil
}

// addMSS installs iptables MSS-clamping + FORWARD ACCEPT rules for dev.
func addMSS(dev string) {
	rules := [][]string{
		{"-t", "mangle", "-A", "FORWARD", "-i", dev, "-p", "tcp",
			"--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"},
		{"-t", "mangle", "-A", "FORWARD", "-o", dev, "-p", "tcp",
			"--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"},
		{"-A", "FORWARD", "-i", dev, "-j", "ACCEPT"},
		{"-A", "FORWARD", "-o", dev, "-j", "ACCEPT"},
	}
	for _, r := range rules {
		iptablesEnsure(r)
	}
}

// delMSS removes iptables rules for dev (best-effort).
func delMSS(dev string) {
	rules := [][]string{
		{"-t", "mangle", "-D", "FORWARD", "-i", dev, "-p", "tcp",
			"--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"},
		{"-t", "mangle", "-D", "FORWARD", "-o", dev, "-p", "tcp",
			"--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"},
		{"-D", "FORWARD", "-i", dev, "-j", "ACCEPT"},
		{"-D", "FORWARD", "-o", dev, "-j", "ACCEPT"},
	}
	for _, r := range rules {
		try("iptables", r...)
	}
}

// iptablesEnsure adds an iptables rule only if it does not already exist.
func iptablesEnsure(rule []string) {
	check := make([]string, len(rule))
	copy(check, rule)
	for i, a := range check {
		if a == "-A" || a == "-I" {
			check[i] = "-C"
			break
		}
	}
	if run("iptables", check...) != nil {
		try("iptables", rule...)
	}
}
