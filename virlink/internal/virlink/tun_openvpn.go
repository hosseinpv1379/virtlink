// tun_openvpn.go — OpenVPN tunnel via the openvpn core (external daemon).
//
// virlink writes no packets itself: it starts openvpn --config, waits for the
// TUN device, and tears the process down on exit.
package virlink

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/vishvananda/netlink"
)

const openvpnSubnet = "10.20.50.0/24"

type OpenvpnTunnel struct {
	cfg     *Config
	cmd     *exec.Cmd
	lockFd  *os.File
	pidPath string
}

func (t *OpenvpnTunnel) DevName() string {
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
	if _, err := os.Stat(ov.Config); err != nil {
		return fmt.Errorf("[openvpn] config %q: %w", ov.Config, err)
	}
	if _, err := exec.LookPath("openvpn"); err != nil {
		return fmt.Errorf("openvpn not found — install: apt install openvpn")
	}

	dev := t.DevName()
	addr := t.OverlayIP()
	peer := t.PeerIP()
	port := c.Transport.Port
	proto := c.Transport.Proto
	if proto == "" {
		proto = "udp"
	}

	header("openvpn / " + c.Mode)
	applyPerfFromConfig(c)
	step("cleanup...")
	t.doClean()

	var err error
	t.lockFd, err = acquireTunnelLock(dev)
	if err != nil {
		return err
	}

	step(fmt.Sprintf("starting openvpn (%s)...", filepath.Base(ov.Config)))
	logPath := openvpnLogPath(c)
	t.pidPath = openvpnPIDPath(c)
	_ = os.MkdirAll(filepath.Dir(logPath), 0o755)
	_ = os.MkdirAll(filepath.Dir(t.pidPath), 0o755)

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("openvpn log: %w", err)
	}

	t.cmd = exec.Command("openvpn",
		"--cd", filepath.Dir(ov.Config),
		"--config", ov.Config,
		"--writepid", t.pidPath,
	)
	t.cmd.Stdout = logFile
	t.cmd.Stderr = logFile
	if err := t.cmd.Start(); err != nil {
		logFile.Close()
		return fmt.Errorf("openvpn start: %w", err)
	}
	go func() { _ = logFile.Close() }()

	step("waiting for TUN device " + dev + "...")
	if err := waitForLink(dev, 30*time.Second); err != nil {
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

	step(fmt.Sprintf("tuning (%s)...", tuningModeLabel(c)))
	applyTunnelTuning(c, dev)
	addMSS(dev)

	logOK(fmt.Sprintf("openvpn running  pid=%d  dev=%s", t.cmd.Process.Pid, dev))
	logOK(fmt.Sprintf("overlay %s  peer %s", addr, peer))

	done(dev, addr, peer,
		fmt.Sprintf("transport : OpenVPN %s :%d", proto, port),
		"config    : "+ov.Config,
		"log       : "+logPath,
		"test      : ping -c3 "+peer,
	)
	return nil
}

func (t *OpenvpnTunnel) Down() error {
	t.doClean()
	logOK("openvpn tunnel torn down")
	return nil
}

func (t *OpenvpnTunnel) doClean() {
	t.stopProcess()
	if t.lockFd != nil {
		releaseTunnelLock(t.lockFd)
		t.lockFd = nil
	}
	restoreTunnelTuning()
	delMSS(t.DevName())
	nlDown(t.DevName())
	if t.pidPath != "" {
		_ = os.Remove(t.pidPath)
		t.pidPath = ""
	}
}

func (t *OpenvpnTunnel) stopProcess() {
	if t.cmd != nil && t.cmd.Process != nil {
		_ = t.cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() {
			_ = t.cmd.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = t.cmd.Process.Kill()
		}
		t.cmd = nil
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
	dev := t.DevName()
	if l, err := netlink.LinkByName(dev); err == nil {
		fmt.Printf("  %s: flags=%v\n", l.Attrs().Name, l.Attrs().Flags)
	}
	if t.cmd != nil && t.cmd.Process != nil {
		fmt.Printf("  openvpn pid: %d\n", t.cmd.Process.Pid)
	}
	fmt.Printf("  config: %s\n", t.cfg.OpenVPN.Config)
}

func waitForLink(name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if l, err := netlink.LinkByName(name); err == nil {
			if l.Attrs().Flags&net.FlagUp != 0 {
				return nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for interface %s", name)
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
