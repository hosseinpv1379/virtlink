// openvpn_multicore.go — DCO (Data Channel Offload) detection for single-IP multi-core throughput.
//
// OpenVPN without DCO is effectively single-threaded for crypto. Extra parallel tunnels on
// different /30 subnets only help ECMP across multiple flows — not one peer IP. DCO moves
// the data channel into the kernel so one overlay IP can use multiple CPU cores.
package virlink

import (
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// openvpnUseDCO decides whether to enable Data Channel Offload (OpenVPN 2.6+).
func openvpnUseDCO(c *Config) bool {
	if c.OpenVPN.DCO != nil {
		return *c.OpenVPN.DCO
	}
	return ovpnDCOModulePresent() && openvpnBinarySupportsDCO()
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

var openvpnVersionRe = regexp.MustCompile(`OpenVPN\s+(\d+)\.(\d+)`)

func openvpnBinarySupportsDCO() bool {
	out, err := exec.Command("openvpn", "--version").CombinedOutput()
	if err != nil {
		return false
	}
	m := openvpnVersionRe.FindSubmatch(out)
	if len(m) < 3 {
		return false
	}
	major, _ := strconv.Atoi(string(m[1]))
	minor, _ := strconv.Atoi(string(m[2]))
	return major > 2 || (major == 2 && minor >= 6)
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
