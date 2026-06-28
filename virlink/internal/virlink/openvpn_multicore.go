// openvpn_multicore.go — DCO detection, worker overlay IPs, multi-instance helpers.
package virlink

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const openvpnMaxWorkers = 4

// openvpnWorkers returns parallel link count (1–4). DCO mode uses 1 process; kernel spreads load.
func openvpnWorkers(c *Config) int {
	n := c.OpenVPN.Workers
	if n <= 0 && c.Tuning.Workers > 0 {
		n = c.Tuning.Workers
	}
	if n <= 0 {
		n = 1
	}
	if n > openvpnMaxWorkers {
		n = openvpnMaxWorkers
	}
	if openvpnUseDCO(c) && n > 1 {
		// One DCO tunnel already uses multiple cores in the kernel.
		return 1
	}
	return n
}

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
	// try loading common module names
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

// openvpnWorkerAddrs returns overlay /30 local CIDR and plain peer IP for worker index w.
func openvpnWorkerAddrs(cfg *Config, worker int) (localCIDR, peerPlain string) {
	subnet := cfg.Tunnel.CIDR
	if subnet == "" {
		subnet = openvpnSubnet
	}
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return overlayAddr(cfg, openvpnSubnet), peerAddr(cfg, openvpnSubnet)
	}
	ip := make(net.IP, 4)
	copy(ip, ipNet.IP.To4())
	ip[3] += byte(worker * 4)

	var localOctet, peerOctet byte
	if cfg.Mode == "client" {
		localOctet = ip[3] + 1
		peerOctet = ip[3] + 2
	} else {
		localOctet = ip[3] + 2
		peerOctet = ip[3] + 1
	}
	local := net.IPv4(ip[0], ip[1], ip[2], localOctet)
	peer := net.IPv4(ip[0], ip[1], ip[2], peerOctet)
	return fmt.Sprintf("%s/30", local.String()), peer.String()
}

// openvpnWorkerDev returns interface name for worker w (ovpn-tun0, ovpn-tun1, …).
func openvpnWorkerDev(cfg *Config, worker int) string {
	base := cfg.OpenVPN.Dev
	if base == "" {
		base = "ovpn-tun0"
	}
	if worker == 0 {
		return base
	}
	// ovpn-tun0 → ovpn-tun1
	if strings.HasSuffix(base, "0") {
		return base[:len(base)-1] + strconv.Itoa(worker)
	}
	return fmt.Sprintf("%s%d", base, worker)
}

// openvpnWorkerConfPath maps base.conf → worker-N.conf (worker 0 keeps base path).
func openvpnWorkerConfPath(base string, worker int) string {
	if worker == 0 {
		return base
	}
	ext := filepath.Ext(base)
 stem := strings.TrimSuffix(base, ext)
	return fmt.Sprintf("%s-%d%s", stem, worker, ext)
}

// openvpnWorkerPort returns UDP/TCP port for worker index.
func openvpnWorkerPort(cfg *Config, worker int) int {
	port := cfg.Transport.Port
	if port == 0 {
		port = 1194
	}
	return port + worker
}
