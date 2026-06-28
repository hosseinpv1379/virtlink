// tun_hysteria2.go — Hysteria2 tunnel via the hysteria core (external daemon).
//
// Server: hysteria server + kernel TUN with overlay IP for health/probes.
// Client: hysteria client with built-in TUN (QUIC/UDP, good for filtered paths).
package virlink

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
)

const hysteria2Subnet = "10.20.52.0/24"

type Hysteria2Tunnel struct {
	cfg     *Config
	cmd     *exec.Cmd
	lockFd  *os.File
	tunFd   *os.File // server: keeps overlay TUN up
	pidPath string
}

func (t *Hysteria2Tunnel) DevName() string {
	if t.cfg.Hysteria2.Dev != "" {
		return t.cfg.Hysteria2.Dev
	}
	return "hy2-tun0"
}

func (t *Hysteria2Tunnel) OverlayIP() string { return overlayAddr(t.cfg, hysteria2Subnet) }
func (t *Hysteria2Tunnel) PeerIP() string    { return peerAddr(t.cfg, hysteria2Subnet) }

func (t *Hysteria2Tunnel) Up() error {
	c := t.cfg
	hy := c.Hysteria2
	if hy.Config == "" {
		return fmt.Errorf("[hysteria2] config path is required")
	}
	if _, err := os.Stat(hy.Config); err != nil {
		return fmt.Errorf("[hysteria2] config %q: %w", hy.Config, err)
	}
	if _, err := exec.LookPath("hysteria"); err != nil {
		return fmt.Errorf("hysteria not found — run: virlink-setup → install hysteria2")
	}

	dev := t.DevName()
	addr := t.OverlayIP()
	peer := t.PeerIP()
	port := c.Transport.Port
	if port == 0 {
		port = 443
	}

	header("hysteria2 / " + c.Mode)
	applyPerfFromConfig(c)
	step("cleanup...")
	t.doClean()

	var err error
	t.lockFd, err = acquireTunnelLock(dev)
	if err != nil {
		return err
	}

	if c.Mode == "server" {
		step("creating overlay TUN " + dev + "...")
		if err := t.setupServerTun(dev, addr); err != nil {
			return err
		}
	}

	subcmd := "client"
	if c.Mode == "server" {
		subcmd = "server"
	}
	step(fmt.Sprintf("starting hysteria %s...", subcmd))
	logPath := hysteria2LogPath(c)
	t.pidPath = hysteria2PIDPath(c)
	_ = os.MkdirAll(filepath.Dir(logPath), 0o755)
	_ = os.MkdirAll(filepath.Dir(t.pidPath), 0o755)

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("hysteria2 log: %w", err)
	}

	t.cmd = exec.Command("hysteria", subcmd, "-c", filepath.Base(hy.Config))
	t.cmd.Dir = filepath.Dir(hy.Config)
	t.cmd.Stdout = logFile
	t.cmd.Stderr = logFile
	if err := t.cmd.Start(); err != nil {
		logFile.Close()
		return fmt.Errorf("hysteria2 start: %w", err)
	}
	go func() { _ = logFile.Close() }()

	step("waiting for TUN device " + dev + "...")
	if err := waitForHysteria2(dev, logPath, t.cmd, c.Mode, 120*time.Second); err != nil {
		t.stopProcess()
		return err
	}

	if l, err := netlink.LinkByName(dev); err == nil && c.Tunnel.MTU > 0 {
		_ = netlink.LinkSetMTU(l, c.Tunnel.MTU)
	}

	step(fmt.Sprintf("tuning (%s)...", tuningModeLabel(c)))
	applyTunnelTuning(c, dev)
	addMSS(dev)

	logOK(fmt.Sprintf("hysteria2 running  pid=%d  dev=%s", t.cmd.Process.Pid, dev))
	logOK(fmt.Sprintf("overlay %s  peer %s", addr, peer))

	done(dev, addr, peer,
		fmt.Sprintf("transport : Hysteria2 QUIC :%d", port),
		"config    : "+hy.Config,
		"log       : "+logPath,
		"test      : ping -c3 "+peer+"  (UDP health probe; ICMP may not traverse hy2 TUN)",
	)
	return nil
}

func (t *Hysteria2Tunnel) setupServerTun(dev, addr string) error {
	fd, err := openTunDev(dev)
	if err != nil {
		return fmt.Errorf("server TUN: %w", err)
	}
	t.tunFd = fd

	l, err := netlink.LinkByName(dev)
	if err != nil {
		return fmt.Errorf("link %s: %w", dev, err)
	}
	mtu := t.cfg.Tunnel.MTU
	if mtu == 0 {
		mtu = 1400
	}
	_ = netlink.LinkSetMTU(l, mtu)
	a, err := netlink.ParseAddr(addr)
	if err != nil {
		return fmt.Errorf("parse overlay %s: %w", addr, err)
	}
	_ = netlink.AddrReplace(l, a)
	if err := netlink.LinkSetUp(l); err != nil {
		return fmt.Errorf("link up %s: %w", dev, err)
	}
	logOK(fmt.Sprintf("%s  %s  (server overlay)", dev, addr))
	return nil
}

func (t *Hysteria2Tunnel) Down() error {
	t.doClean()
	logOK("hysteria2 tunnel torn down")
	return nil
}

func (t *Hysteria2Tunnel) doClean() {
	t.stopProcess()
	if t.tunFd != nil {
		_ = t.tunFd.Close()
		t.tunFd = nil
	}
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

func (t *Hysteria2Tunnel) stopProcess() {
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
}

func (t *Hysteria2Tunnel) Status() {
	dev := t.DevName()
	if l, err := netlink.LinkByName(dev); err == nil {
		fmt.Printf("  %s: flags=%v\n", l.Attrs().Name, l.Attrs().Flags)
	}
	if t.cmd != nil && t.cmd.Process != nil {
		fmt.Printf("  hysteria pid: %d\n", t.cmd.Process.Pid)
	}
	fmt.Printf("  config: %s\n", t.cfg.Hysteria2.Config)
}

func waitForHysteria2(dev, logPath string, cmd *exec.Cmd, mode string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cmd != nil && !hysteria2ProcessAlive(cmd) {
			return fmt.Errorf("hysteria exited before %s came up:\n%s",
				dev, hysteria2LogTail(logPath, 25))
		}
		if !linkUp(dev) {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		if mode == "server" {
			if logPath == "" || hysteria2LogContains(logPath, "server mode") ||
				hysteria2LogContains(logPath, "listening") {
				return nil
			}
		} else if logPath == "" || hysteria2LogContains(logPath, "TUN listening") {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	hint := "start hysteria2 server first; match port/auth/TLS; open firewall UDP (QUIC) to server"
	if logPath != "" {
		return fmt.Errorf("timeout waiting for %s (%s):\n%s\nlog: %s",
			dev, hint, hysteria2LogTail(logPath, 25), logPath)
	}
	return fmt.Errorf("timeout waiting for interface %s", dev)
}

func hysteria2ProcessAlive(cmd *exec.Cmd) bool {
	if cmd == nil || cmd.Process == nil {
		return false
	}
	return cmd.Process.Signal(syscall.Signal(0)) == nil
}

func hysteria2LogContains(path, needle string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return bytes.Contains(b, []byte(needle))
}

func hysteria2LogTail(path string, n int) string {
	if path == "" {
		return "(no log path)"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("(log unreadable: %v)", err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) == 0 {
		return "(log empty — hysteria failed immediately?)"
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func hysteria2LogPath(c *Config) string {
	name := tunnelInstanceName(c)
	return filepath.Join("/var/log/virlink", name+"-hysteria2.log")
}

func hysteria2PIDPath(c *Config) string {
	name := tunnelInstanceName(c)
	return filepath.Join("/var/run/virlink", name+"-hysteria2.pid")
}
