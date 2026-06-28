// tun_openvpn.go — OpenVPN tunnel via the openvpn core (external daemon).
//
// Multi-core throughput:
//   • DCO (Data Channel Offload, OpenVPN 2.6+): one process, crypto in kernel across CPUs.
//   • workers > 1 (no DCO): parallel OpenVPN links on consecutive ports / /30 blocks.
package virlink

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
)

const openvpnSubnet = "10.20.50.0/24"

type openvpnProc struct {
	cmd  *exec.Cmd
	dev  string
	peer string
}

type OpenvpnTunnel struct {
	cfg       *Config
	procs     []openvpnProc
	lockFd    *os.File
	pidPath   string
	useDCO    bool
	workers   int
}

func (t *OpenvpnTunnel) DevName() string {
	if len(t.procs) > 0 {
		return t.procs[0].dev
	}
	if t.cfg.OpenVPN.Dev != "" {
		return t.cfg.OpenVPN.Dev
	}
	return "ovpn-tun0"
}

func (t *OpenvpnTunnel) OverlayIP() string { return overlayAddr(t.cfg, openvpnSubnet) }
func (t *OpenvpnTunnel) PeerIP() string    { return peerAddr(t.cfg, openvpnSubnet) }

func (t *OpenvpnTunnel) Up() error {
	c := t.cfg
	ov := c.OpenVPN
	if ov.Config == "" {
		return fmt.Errorf("[openvpn] config path is required")
	}
	if _, err := exec.LookPath("openvpn"); err != nil {
		return fmt.Errorf("openvpn not found — install: apt install openvpn")
	}

	t.useDCO = openvpnUseDCO(c)
	t.workers = openvpnWorkers(c)
	dev0 := openvpnWorkerDev(c, 0)

	header("openvpn / " + c.Mode)
	if t.useDCO {
		logInfo("DCO enabled — kernel multi-core data channel (OpenVPN 2.6+)")
	} else if t.workers > 1 {
		logInfo(fmt.Sprintf("parallel links: %d  (multi-path, no DCO)", t.workers))
	} else {
		logInfo("single OpenVPN process (user-space crypto — install ovpn-dco for multi-core)")
	}

	applyPerfFromConfig(c)
	step("cleanup...")
	t.doClean()

	var err error
	t.lockFd, err = acquireTunnelLock(dev0)
	if err != nil {
		return err
	}

	logPath := openvpnLogPath(c)
	t.pidPath = openvpnPIDPath(c)
	_ = os.MkdirAll(filepath.Dir(logPath), 0o755)
	_ = os.MkdirAll(filepath.Dir(t.pidPath), 0o755)

	for w := 0; w < t.workers; w++ {
		conf := openvpnWorkerConfPath(ov.Config, w)
		if _, err := os.Stat(conf); err != nil {
			return fmt.Errorf("[openvpn] config %q: %w", conf, err)
		}
		dev := openvpnWorkerDev(c, w)
		_, peerPlain := openvpnWorkerAddrs(c, w)
		step(fmt.Sprintf("starting openvpn worker %d/%d (%s)...", w+1, t.workers, filepath.Base(conf)))

		logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return fmt.Errorf("openvpn log: %w", err)
		}

		args := []string{
			"--cd", filepath.Dir(conf),
			"--config", filepath.Base(conf),
		}
		if w == 0 {
			args = append(args, "--writepid", t.pidPath)
		}
		if t.useDCO {
			args = append(args, "--enable-dco")
		} else {
			args = append(args, "--disable-dco")
		}

		cmd := exec.Command("openvpn", args...)
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		if err := cmd.Start(); err != nil {
			logFile.Close()
			t.stopProcesses()
			return fmt.Errorf("openvpn start worker %d: %w", w, err)
		}
		go func() { _ = logFile.Close() }()

		step("waiting for TUN " + dev + "...")
		if err := waitForOpenVPN(dev, logPath, cmd, 120*time.Second); err != nil {
			t.stopProcesses()
			return err
		}

		l, err := netlink.LinkByName(dev)
		if err != nil {
			t.stopProcesses()
			return fmt.Errorf("link %s: %w", dev, err)
		}
		if c.Tunnel.MTU > 0 {
			_ = netlink.LinkSetMTU(l, c.Tunnel.MTU)
		}

		t.procs = append(t.procs, openvpnProc{cmd: cmd, dev: dev, peer: peerPlain})
	}

	if t.workers > 1 && !t.useDCO {
		step("ECMP overlay routes (multi-path)...")
		if err := t.installWorkerECMP(); err != nil {
			logWarn("ecmp: " + err.Error())
		}
	}

	step(fmt.Sprintf("tuning (%s)...", tuningModeLabel(c)))
	devs := make([]string, len(t.procs))
	for i, p := range t.procs {
		devs[i] = p.dev
	}
	applyTunnelTuning(c, devs...)
	for _, d := range devs {
		addMSS(d)
	}

	if t.useDCO {
		t.logDCOStatus(logPath)
	}

	addr := t.OverlayIP()
	peer := t.PeerIP()
	extra := []string{
		fmt.Sprintf("transport : OpenVPN %s", c.Transport.Proto),
		"config    : " + ov.Config,
		"log       : " + logPath,
		"test      : ping -c3 " + peer,
	}
	if t.workers > 1 && !t.useDCO {
		var peers []string
		for _, p := range t.procs {
			peers = append(peers, p.peer)
		}
		extra = append(extra,
			fmt.Sprintf("workers   : %d parallel links", t.workers),
			"peers     : "+strings.Join(peers, "  "),
			"bench     : iperf3 -P"+fmt.Sprint(t.workers)+" or run iperf to each peer IP",
		)
	}
	if len(t.procs) > 0 && t.procs[0].cmd.Process != nil {
		logOK(fmt.Sprintf("openvpn running  workers=%d  pid=%d  dev=%s", t.workers, t.procs[0].cmd.Process.Pid, t.DevName()))
	}
	logOK(fmt.Sprintf("overlay %s  peer %s", addr, peer))
	done(t.DevName(), addr, peer, extra...)
	return nil
}

func (t *OpenvpnTunnel) installWorkerECMP() error {
	if len(t.procs) < 2 {
		return nil
	}
	// ECMP toward the aggregate overlay prefix so flows hash across links.
	subnet := t.cfg.Tunnel.CIDR
	if subnet == "" {
		subnet = openvpnSubnet
	}
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return err
	}
	ones, _ := ipNet.Mask.Size()
	if ones > 28 {
		ones = 28
	}
	mask := net.CIDRMask(ones, 32)
	dst := &net.IPNet{IP: ipNet.IP.To4().Mask(mask), Mask: mask}

	devs := make([]string, len(t.procs))
	for i, p := range t.procs {
		devs[i] = p.dev
	}
	_ = netlink.RouteDel(&netlink.Route{Dst: dst})
	route := &netlink.Route{Dst: dst}
	for _, name := range devs {
		l, err := netlink.LinkByName(name)
		if err != nil {
			return err
		}
		route.MultiPath = append(route.MultiPath, &netlink.NexthopInfo{
			LinkIndex: l.Attrs().Index,
		})
	}
	if err := netlink.RouteAdd(route); err != nil {
		return err
	}
	logOK(fmt.Sprintf("ECMP %s via %s", dst, strings.Join(devs, " + ")))
	return nil
}

func (t *OpenvpnTunnel) logDCOStatus(logPath string) {
	if logPath == "" {
		return
	}
	b, err := os.ReadFile(logPath)
	if err != nil {
		return
	}
	s := string(b)
	switch {
	case strings.Contains(s, "Data Channel Offload"):
		logOK("DCO active — crypto handled in kernel")
	case strings.Contains(s, "disabling data channel offload"):
		logWarn("DCO unavailable — falling back to single-thread user-space")
	}
}

func (t *OpenvpnTunnel) Down() error {
	t.doClean()
	logOK("openvpn tunnel torn down")
	return nil
}

func (t *OpenvpnTunnel) doClean() {
	t.stopProcesses()
	if t.lockFd != nil {
		releaseTunnelLock(t.lockFd)
		t.lockFd = nil
	}
	restoreTunnelTuning()
	if len(t.procs) > 0 {
		devs := make([]string, len(t.procs))
		for i, p := range t.procs {
			devs[i] = p.dev
		}
		for _, d := range devs {
			delMSS(d)
			nlDown(d)
		}
	}
	t.procs = nil
	if t.pidPath != "" {
		_ = os.Remove(t.pidPath)
		t.pidPath = ""
	}
}

func (t *OpenvpnTunnel) stopProcesses() {
	for _, p := range t.procs {
		if p.cmd != nil && p.cmd.Process != nil {
			_ = p.cmd.Process.Signal(os.Interrupt)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for _, p := range t.procs {
		if p.cmd == nil || p.cmd.Process == nil {
			continue
		}
		done := make(chan struct{})
		go func(cmd *exec.Cmd) {
			_ = cmd.Wait()
			close(done)
		}(p.cmd)
		select {
		case <-done:
		case <-time.After(time.Until(deadline)):
			_ = p.cmd.Process.Kill()
		}
	}
	if t.pidPath != "" {
		if b, err := os.ReadFile(t.pidPath); err == nil {
			var pid int
			if _, err := fmt.Sscanf(string(b), "%d", &pid); err == nil && pid > 1 {
				try("kill", fmt.Sprint(pid))
			}
		}
	}
}

func (t *OpenvpnTunnel) Status() {
	for _, p := range t.procs {
		if l, err := netlink.LinkByName(p.dev); err == nil {
			fmt.Printf("  %s: flags=%v  peer=%s\n", l.Attrs().Name, l.Attrs().Flags, p.peer)
		}
		if p.cmd != nil && p.cmd.Process != nil {
			fmt.Printf("  openvpn pid: %d  dev=%s\n", p.cmd.Process.Pid, p.dev)
		}
	}
	fmt.Printf("  config: %s\n", t.cfg.OpenVPN.Config)
	fmt.Printf("  workers: %d  dco: %v\n", t.workers, t.useDCO)
}

func waitForLink(name string, timeout time.Duration) error {
	return waitForOpenVPN(name, "", nil, timeout)
}

func waitForOpenVPN(dev, logPath string, cmd *exec.Cmd, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if linkUp(dev) {
			return nil
		}
		if logPath != "" && openvpnLogContains(logPath, "Initialization Sequence Completed") {
			time.Sleep(500 * time.Millisecond)
			if linkUp(dev) {
				return nil
			}
		}
		if cmd != nil && !openvpnProcessAlive(cmd) {
			return fmt.Errorf("openvpn exited before %s came up:\n%s",
				dev, openvpnLogTail(logPath, 20))
		}
		time.Sleep(250 * time.Millisecond)
	}
	hint := "start OpenVPN server first; match port/proto/PKI; open firewall; for multi-core install ovpn-dco"
	if logPath != "" {
		return fmt.Errorf("timeout waiting for %s (%s):\n%s\nlog: %s",
			dev, hint, openvpnLogTail(logPath, 25), logPath)
	}
	return fmt.Errorf("timeout waiting for interface %s", dev)
}

func linkUp(name string) bool {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return false
	}
	return l.Attrs().Flags&net.FlagUp != 0
}

func openvpnProcessAlive(cmd *exec.Cmd) bool {
	if cmd == nil || cmd.Process == nil {
		return false
	}
	return cmd.Process.Signal(syscall.Signal(0)) == nil
}

func openvpnLogContains(path, needle string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return bytes.Contains(b, []byte(needle))
}

func openvpnLogTail(path string, n int) string {
	if path == "" {
		return "(no log path)"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("(log unreadable: %v)", err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) == 0 {
		return "(log empty — openvpn failed immediately?)"
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func openvpnLogPath(c *Config) string {
	name := tunnelInstanceName(c)
	return filepath.Join("/var/log/virlink", name+"-openvpn.log")
}

func openvpnPIDPath(c *Config) string {
	name := tunnelInstanceName(c)
	return filepath.Join("/var/run/virlink", name+"-openvpn.pid")
}

func tunnelInstanceName(c *Config) string {
	if c.Tunnel.Name != "" {
		return c.Tunnel.Name
	}
	return c.Tunnel.Type + "-" + c.Tunnel.Mode
}
