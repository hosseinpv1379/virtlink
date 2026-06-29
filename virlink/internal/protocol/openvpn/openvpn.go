// tun_openvpn.go — OpenVPN tunnel via the openvpn core (external daemon).
//
// Multi-core bandwidth on a single overlay IP requires DCO (OpenVPN 2.6+ + ovpn-dco module).
// Without DCO, crypto runs in one user-space thread — iperf3 -P helps but each flow is capped.
package openvpn

import (
	"virlink/internal/platform"
	"virlink/internal/core"
	"virlink/internal/config"
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

type OpenvpnTunnel struct {
	cfg     *config.Config
	cmd     *exec.Cmd
	lockFd  *os.File
	pidPath string
	useDCO  bool
}

func (t *OpenvpnTunnel) DevName() string {
	if t.cfg.OpenVPN.Dev != "" {
		return t.cfg.OpenVPN.Dev
	}
	return platform.TunnelDevName(t.cfg, "ovpn-tun0")
}

func (t *OpenvpnTunnel) OverlayIP() string { return core.OverlayAddr(t.cfg, openvpnSubnet) }
func (t *OpenvpnTunnel) PeerIP() string    { return core.PeerAddr(t.cfg, openvpnSubnet) }

func (t *OpenvpnTunnel) Up() error {
	c := t.cfg
	ov := c.OpenVPN
	if ov.Config == "" {
		return fmt.Errorf("[openvpn] config path is required")
	}
	if _, err := os.Stat(ov.Config); err != nil {
		return fmt.Errorf("[openvpn] config %q: %w", ov.Config, err)
	}
	if _, err := exec.LookPath("openvpn"); err != nil {
		return fmt.Errorf("openvpn not found — install: apt install openvpn")
	}

	if c.OpenVPN.Workers > 1 {
		platform.LogWarn(fmt.Sprintf("openvpn workers=%d ignored — extra links use separate overlay IPs and do not raise bandwidth to one peer; install ovpn-dco for multi-core on a single IP", c.OpenVPN.Workers))
	}

	t.useDCO = platform.OpenvpnUseDCO(c)
	dev := t.DevName()
	addr := t.OverlayIP()
	peer := t.PeerIP()
	port := c.Transport.Port
	proto := c.Transport.Proto
	if proto == "" {
		proto = "udp"
	}

	platform.Header("openvpn / " + c.Mode)
	if t.useDCO {
		platform.LogInfo("DCO enabled — single overlay IP, kernel multi-core data channel")
	} else {
		platform.LogWarn("DCO off — user-space crypto (~1 core per flow); install OpenVPN 2.6+ and ovpn-dco for max bandwidth to one peer IP")
	}

	platform.ApplyPerfFromConfig(c)
	platform.Step("cleanup...")
	t.doClean()

	var err error
	t.lockFd, err = platform.AcquireTunnelLock(dev)
	if err != nil {
		return err
	}

	logPath := openvpnLogPath(c)
	t.pidPath = openvpnPIDPath(c)
	_ = os.MkdirAll(filepath.Dir(logPath), 0o755)
	_ = os.MkdirAll(filepath.Dir(t.pidPath), 0o755)

	platform.Step(fmt.Sprintf("starting openvpn (%s)...", filepath.Base(ov.Config)))
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("openvpn log: %w", err)
	}

	args := []string{
		"--cd", filepath.Dir(ov.Config),
		"--config", filepath.Base(ov.Config),
		"--dev", dev,
		"--writepid", t.pidPath,
	}
	if t.useDCO {
		args = append(args, "--enable-dco")
	}
	// omit --disable-dco when unsupported — stock 2.6 without DCO rejects unknown options

	t.cmd = exec.Command("openvpn", args...)
	t.cmd.Stdout = logFile
	t.cmd.Stderr = logFile
	if err := t.cmd.Start(); err != nil {
		logFile.Close()
		return fmt.Errorf("openvpn start: %w", err)
	}
	go func() { _ = logFile.Close() }()

	platform.Step("waiting for TUN device " + dev + "...")
	if err := WaitForOpenVPNWorker(dev, logPath, t.cmd, c.Tunnel.Mode == "server", 120*time.Second); err != nil {
		t.stopProcess()
		return err
	}

	l, err := netlink.LinkByName(dev)
	if err != nil {
		t.stopProcess()
		return fmt.Errorf("link %s: %w", dev, err)
	}
	if c.Tunnel.MTU > 0 {
		_ = netlink.LinkSetMTU(l, c.Tunnel.MTU)
	}

	platform.Step(fmt.Sprintf("tuning (%s)...", platform.TuningModeLabel(c)))
	platform.ApplyTunnelTuning(c, dev)
	platform.AddMSS(c, dev)

	if t.useDCO {
		t.logDCOStatus(logPath)
		if !platform.OpenvpnDCOActive(logPath) {
			platform.LogWarn("DCO was requested but is not active in the log — throughput may be single-threaded")
		}
	}

	if t.cmd.Process != nil {
		platform.LogOK(fmt.Sprintf("openvpn running  pid=%d  dev=%s  dco=%v", t.cmd.Process.Pid, dev, platform.OpenvpnDCOActive(logPath)))
	}
	platform.LogOK(fmt.Sprintf("overlay %s  peer %s", addr, peer))

	extra := []string{
		fmt.Sprintf("transport : OpenVPN %s :%d", proto, port),
		"config    : " + ov.Config,
		"log       : " + logPath,
		"test      : ping -c3 " + peer,
	}
	if t.useDCO && platform.OpenvpnDCOActive(logPath) {
		extra = append(extra, "bench     : iperf3 -t30 (single flow uses multiple cores via DCO)")
	} else {
		extra = append(extra, "bench     : iperf3 -P4 for parallel flows, or enable DCO for one-IP multi-core")
	}
	platform.Done(dev, addr, peer, extra...)
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
		platform.LogOK("DCO active — crypto handled in kernel")
	case strings.Contains(s, "disabling data channel offload"):
		platform.LogWarn("DCO unavailable — falling back to single-thread user-space")
	}
}

func (t *OpenvpnTunnel) Down() error {
	t.doClean()
	platform.LogOK("openvpn tunnel torn down")
	return nil
}

func (t *OpenvpnTunnel) doClean() {
	t.stopProcess()
	if t.lockFd != nil {
		platform.ReleaseTunnelLock(t.lockFd)
		t.lockFd = nil
	}
	platform.RestoreTunnelTuning()
	platform.DelMSS(t.DevName())
	platform.NlDown(t.DevName())
	if t.pidPath != "" {
		_ = os.Remove(t.pidPath)
		t.pidPath = ""
	}
}

func (t *OpenvpnTunnel) stopProcess() {
	if t.cmd != nil && t.cmd.Process != nil {
		_ = t.cmd.Process.Signal(os.Interrupt)
		doneCh := make(chan struct{})
		go func() {
			_ = t.cmd.Wait()
			close(doneCh)
		}()
		select {
		case <-doneCh:
		case <-time.After(5 * time.Second):
			_ = t.cmd.Process.Kill()
		}
	}
	t.cmd = nil
	if t.pidPath != "" {
		if b, err := os.ReadFile(t.pidPath); err == nil {
			var pid int
			if _, err := fmt.Sscanf(string(b), "%d", &pid); err == nil && pid > 1 {
				platform.Try("kill", fmt.Sprint(pid))
			}
		}
	}
}

func (t *OpenvpnTunnel) Status() {
	dev := t.DevName()
	if l, err := netlink.LinkByName(dev); err == nil {
		fmt.Printf("  %s: flags=%v\n", l.Attrs().Name, l.Attrs().Flags)
	}
	if t.cmd != nil && t.cmd.Process != nil {
		fmt.Printf("  openvpn pid: %d\n", t.cmd.Process.Pid)
	}
	fmt.Printf("  config: %s\n", t.cfg.OpenVPN.Config)
	fmt.Printf("  dco: %v\n", t.useDCO)
}

func waitForLink(name string, timeout time.Duration) error {
	return waitForOpenVPN(name, "", nil, timeout)
}

func waitForOpenVPN(dev, logPath string, cmd *exec.Cmd, timeout time.Duration) error {
	return WaitForOpenVPNWorker(dev, logPath, cmd, false, timeout)
}

// WaitForOpenVPNWorker waits for a worker TUN. Server mode accepts earlier log lines and
// fails fast on bind/tun errors instead of sitting until timeout.
func WaitForOpenVPNWorker(dev, logPath string, cmd *exec.Cmd, serverMode bool, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	fatalNeedles := []string{
		"BIND failed",
		"Cannot ioctl TUNSETIFF",
		"Failed to open tun/tap interface",
		"Exiting due to fatal error",
	}
	clientFatalNeedles := []string{
		"AUTH_FAILED",
		"TLS handshake failed",
		"Connection refused",
		"Connection timed out",
		"Inactivity timeout",
		"SIGUSR1[soft",
	}
	for time.Now().Before(deadline) {
		if logPath != "" {
			for _, needle := range fatalNeedles {
				if openvpnLogContains(logPath, needle) {
					return fmt.Errorf("openvpn failed on %s:\n%s", dev, openvpnLogTail(logPath, 30))
				}
			}
			if !serverMode {
				for _, needle := range clientFatalNeedles {
					if openvpnLogContains(logPath, needle) {
						return fmt.Errorf("openvpn client failed on %s:\n%s", dev, openvpnLogTail(logPath, 30))
					}
				}
			}
			if openvpnLogContains(logPath, "Initialization Sequence Completed") {
				time.Sleep(300 * time.Millisecond)
				if linkUp(dev) {
					return nil
				}
			}
		}
		// Server: TUN up / listening is enough (client may connect later).
		// Client: never accept linkUp alone — tun can exist before the session is live.
		if serverMode {
			if linkUp(dev) {
				return nil
			}
			if logPath != "" {
				if openvpnLogContains(logPath, "TUN/TAP device "+dev+" opened") ||
					openvpnLogContains(logPath, "Listening for incoming") {
					time.Sleep(300 * time.Millisecond)
					if linkUp(dev) {
						return nil
					}
				}
			}
		}
		if cmd != nil && !OpenvpnProcessAlive(cmd) {
			return fmt.Errorf("openvpn exited before %s came up:\n%s",
				dev, openvpnLogTail(logPath, 25))
		}
		time.Sleep(250 * time.Millisecond)
	}
	hint := "match port/proto/PKI; open firewall UDP to server; check worker log"
	if serverMode {
		hint = "check port not in use (ss -ulnp); stale worker: kill openvpn / ip link del " + dev
	}
	if logPath != "" {
		return fmt.Errorf("timeout waiting for %s (%s):\n%s\nlog: %s",
			dev, hint, openvpnLogTail(logPath, 25), logPath)
	}
	return fmt.Errorf("timeout waiting for interface %s", dev)
}

// openvpnKillStalePID stops a leftover openvpn from a prior virlink platform.Run (pid file).
func OpenvpnKillStalePID(pidPath string) {
	b, err := os.ReadFile(pidPath)
	if err != nil {
		_ = os.Remove(pidPath)
		return
	}
	var pid int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(b)), "%d", &pid); err != nil || pid <= 1 {
		_ = os.Remove(pidPath)
		return
	}
	if p, err := os.FindProcess(pid); err == nil {
		_ = p.Signal(syscall.SIGINT)
		time.Sleep(300 * time.Millisecond)
		if p.Signal(syscall.Signal(0)) == nil {
			_ = p.Kill()
		}
	}
	_ = os.Remove(pidPath)
}

func linkUp(name string) bool {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return false
	}
	return l.Attrs().Flags&net.FlagUp != 0
}

func OpenvpnProcessAlive(cmd *exec.Cmd) bool {
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

func openvpnLogPath(c *config.Config) string {
	name := tunnelInstanceName(c)
	return filepath.Join("/var/log/virlink", name+"-openvpn.log")
}

func openvpnPIDPath(c *config.Config) string {
	name := tunnelInstanceName(c)
	return filepath.Join("/var/run/virlink", name+"-openvpn.pid")
}

func tunnelInstanceName(c *config.Config) string {
	if c.Tunnel.Name != "" {
		return c.Tunnel.Name
	}
	return c.Tunnel.Type + "-" + c.Tunnel.Mode
}
