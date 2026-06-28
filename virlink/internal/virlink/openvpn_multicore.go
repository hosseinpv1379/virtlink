// openvpn_multicore.go — DCO (Data Channel Offload) detection for single-IP multi-core throughput.
//
// OpenVPN without DCO is effectively single-threaded for crypto. Extra parallel tunnels on
// different /30 subnets only help ECMP across multiple flows — not one peer IP. DCO moves
// the data channel into the kernel so one overlay IP can use multiple CPU cores.
package virlink

import (
	"os"
	"os/exec"
	"strings"
)

// openvpnUseDCO decides whether to enable Data Channel Offload (OpenVPN 2.6+ built with DCO).
func openvpnUseDCO(c *Config) bool {
	supported := openvpnBinarySupportsDCO()
	module := ovpnDCOModulePresent()
	if c.OpenVPN.DCO != nil && *c.OpenVPN.DCO {
		if !supported {
			logWarn("dco=true but openvpn lacks DCO (enable-dco unknown) — install openvpn-dco-dkms or rebuild; running without DCO")
			return false
		}
		if !module {
			logWarn("dco=true but ovpn-dco kernel module missing — modprobe ovpn_dco_v2; running without DCO")
			return false
		}
		return true
	}
	if c.OpenVPN.DCO != nil && !*c.OpenVPN.DCO {
		return false
	}
	return supported && module
}

func ovpnDCOModulePresent() bool {
	for _, name := range []string{"ovpn_dco_v2", "ovpn_dco", "ovpn"} {
		if _, err := os.Stat("/sys/module/" + name); err == nil {
			return true
		}
	}
	for _, mod := range []string{"ovpn_dco_v2", "ovpn_dco", "ovpn"} {
		_ = exec.Command("modprobe", mod).Run()
		if _, err := os.Stat("/sys/module/" + mod); err == nil {
			return true
		}
	}
	return false
}

func openvpnBinarySupportsDCO() bool {
	out, err := exec.Command("openvpn", "--help").CombinedOutput()
	if err != nil {
		return false
	}
	// Version 2.6+ alone is not enough — distro packages often omit DCO at compile time.
	return strings.Contains(string(out), "enable-dco")
}

func openvpnDCOActive(logPath string) bool {
	if logPath == "" {
		return false
	}
	b, err := os.ReadFile(logPath)
	if err != nil {
		return false
	}
	s := string(b)
	return strings.Contains(s, "Data Channel Offload") &&
		!strings.Contains(s, "disabling data channel offload")
}
