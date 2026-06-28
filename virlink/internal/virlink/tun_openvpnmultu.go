// tun_openvpnmultu.go — parallel OpenVPN workers + kernel ECMP load-balancing.
//
// N independent openvpn processes (one CPU thread each) share the same overlay peer IP
// via per-flow ECMP routing — same idea as bonded-gre-fou, without touching tun_openvpn.go.
package virlink

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
)

const (
	openvpnMultuSubnet     = "10.20.50.0/24"
	openvpnMultuMaxWorkers = 8
)

type openvpnMultuWorker struct {
	index   int
	dev     string
	conf    string
	logPath string
	pidPath string
	cmd     *exec.Cmd
}

type OpenvpnMultuTunnel struct {
	cfg        *Config
	workers    []openvpnMultuWorker
	runtimeDir string
	lockFd     *os.File
	loAddr     string
}

func (t *OpenvpnMultuTunnel) DevName() string {
	if len(t.workers) > 0 {
		return t.workers[0].dev
	}
	return "ovpnm-w0"
}

func (t *OpenvpnMultuTunnel) OverlayIP() string { return overlayAddr(t.cfg, openvpnMultuSubnet) }
func (t *OpenvpnMultuTunnel) PeerIP() string    { return peerAddr(t.cfg, openvpnMultuSubnet) }

func (t *OpenvpnMultuTunnel) Up() error {
	c := t.cfg
	n := c.OpenVPNMultu.Workers
	if n < 2 {
		return fmt.Errorf("[openvpnmultu] workers must be 2–%d, got %d", openvpnMultuMaxWorkers, n)
	}
	if n > openvpnMultuMaxWorkers {
		return fmt.Errorf("[openvpnmultu] workers must be 2–%d, got %d", openvpnMultuMaxWorkers, n)
	}
	pkiDir := strings.TrimSpace(c.OpenVPNMultu.PKIDir)
	if pkiDir == "" {
		return fmt.Errorf("[openvpnmultu] pki_dir is required")
	}
	if _, err := os.Stat(pkiDir); err != nil {
		return fmt.Errorf("[openvpnmultu] pki_dir %q: %w", pkiDir, err)
	}
	if _, err := exec.LookPath("openvpn"); err != nil {
		return fmt.Errorf("openvpn not found — install: apt install openvpn")
	}

	header("openvpnmultu / " + c.Mode)
	logInfo(fmt.Sprintf("%d parallel OpenVPN workers + ECMP flow-hash load-balancer", n))
	logWarn("DCO is disabled per worker — use openvpnmultu for multi-process bandwidth without ovpn-dco")

	applyPerfFromConfig(c)
	step("cleanup...")
	t.doClean() // kills stale worker PIDs / TUNs even when t.workers is empty (restart)

	var err error
	t.lockFd, err = acquireTunnelLock("ovpnm-" + tunnelInstanceName(c))
	if err != nil {
		return err
	}

	step(fmt.Sprintf("materializing %d worker configs...", n))
	t.runtimeDir, err = openvpnMultuMaterializeWorkers(c)
	if err != nil {
		t.doClean()
		return err
	}

	t.workers = make([]openvpnMultuWorker, n)
	for i := 0; i < n; i++ {
		w := &t.workers[i]
		w.index = i
		w.dev = fmt.Sprintf("ovpnm-w%d", i)
		w.conf = openvpnMultuWorkerConfPath(c, i)
		w.logPath = openvpnMultuWorkerLogPath(c, i)
		w.pidPath = openvpnMultuWorkerPIDPath(c, i)
		_ = os.MkdirAll(filepath.Dir(w.logPath), 0o755)
		_ = os.MkdirAll(filepath.Dir(w.pidPath), 0o755)

		step(fmt.Sprintf("starting worker %d/%d (%s)...", i+1, n, filepath.Base(w.conf)))
		if err := t.startWorker(w); err != nil {
			t.doClean()
			return err
		}
		waitTimeout := 120 * time.Second
		if c.Mode == "server" {
			waitTimeout = 45 * time.Second
		}
		if err := waitForOpenVPNWorker(w.dev, w.logPath, w.cmd, c.Mode == "server", waitTimeout); err != nil {
			t.doClean()
			return fmt.Errorf("worker %d: %w", i, err)
		}
		if c.Tunnel.MTU > 0 {
			if l, e := netlink.LinkByName(w.dev); e == nil {
				_ = netlink.LinkSetMTU(l, c.Tunnel.MTU)
			}
		}
		logOK(fmt.Sprintf("worker %d up  dev=%s  log=%s", i, w.dev, w.logPath))
	}

	overlay := t.OverlayIP()
	peer := t.PeerIP()
	localPlain := plainIP(overlay)

	step("overlay on lo (peer routes via workers when sessions connect)...")
	if err := t.setupOverlayRouting(localPlain, peer); err != nil {
		t.doClean()
		return err
	}

	devs := make([]string, n)
	for i := range t.workers {
		devs[i] = t.workers[i].dev
	}
	step(fmt.Sprintf("tuning (%s, multipath)...", tuningModeLabel(c)))
	c.Tuning.Multipath = true
	applyTunnelTuning(c, devs...)
	for _, d := range devs {
		addMSS(d)
	}

	ports := openvpnMultuPortRange(c)
	done(t.DevName(), overlay, peer,
		fmt.Sprintf("workers   : %d parallel openvpn (no DCO)", n),
		fmt.Sprintf("transport : OpenVPN %s ports %s", c.Transport.Proto, ports),
		"routing   : per-worker overlay routes → kernel ECMP when all sessions up",
		"pki       : "+pkiDir+"  (PKI only — worker configs internal)",
		"runtime   : workers materialized at "+t.runtimeDir,
		"bench     : iperf3 -P"+fmt.Sprint(n)+" -c "+peer,
	)
	return nil
}

func openvpnMultuPreclean(c *Config) {
	if c == nil {
		return
	}
	n := c.OpenVPNMultu.Workers
	if peer := peerAddr(c, openvpnMultuSubnet); peer != "" {
		nlRouteDelAll(peer)
	}
	for i := 0; i < n; i++ {
		dev := fmt.Sprintf("ovpnm-w%d", i)
		openvpnKillStalePID(openvpnMultuWorkerPIDPath(c, i))
		delMSS(dev)
		nlDown(dev)
	}
}

func (t *OpenvpnMultuTunnel) startWorker(w *openvpnMultuWorker) error {
	logFile, err := os.OpenFile(w.logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("openvpn log: %w", err)
	}
	args := []string{
		"--cd", filepath.Dir(w.conf),
		"--config", filepath.Base(w.conf),
		"--writepid", w.pidPath,
		"--disable-dco",
	}
	w.cmd = exec.Command("openvpn", args...)
	w.cmd.Stdout = logFile
	w.cmd.Stderr = logFile
	if err := w.cmd.Start(); err != nil {
		logFile.Close()
		return fmt.Errorf("openvpn start: %w", err)
	}
	go func() { _ = logFile.Close() }()
	return nil
}

func (t *OpenvpnMultuTunnel) setupOverlayRouting(localPlain, peer string) error {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("lo: %w", err)
	}
	t.loAddr = localPlain + "/32"
	addr, err := netlink.ParseAddr(t.loAddr)
	if err != nil {
		return fmt.Errorf("parse overlay addr: %w", err)
	}
	_ = netlink.AddrDel(lo, addr) // idempotent replace
	if err := netlink.AddrAdd(lo, addr); err != nil {
		return fmt.Errorf("addr add lo %s: %w", t.loAddr, err)
	}

	devs := make([]string, len(t.workers))
	for i := range t.workers {
		devs[i] = t.workers[i].dev
	}
	// Do not install kernel ECMP before OpenVPN sessions exist — traffic would be
	// hashed to workers with no peer. Each worker adds route peer/32 on connect;
	// the kernel load-balances once multiple worker routes are present.
	logOK(fmt.Sprintf("lo %s  peer %s/32 via workers %v (routes appear per session)", t.loAddr, peer, devs))
	return nil
}

func openvpnMultuPortRange(c *Config) string {
	base := c.Transport.Port
	if base == 0 {
		base = 1194
	}
	n := c.OpenVPNMultu.Workers
	if n <= 1 {
		return fmt.Sprint(base)
	}
	return fmt.Sprintf("%d–%d", base, base+n-1)
}

func openvpnMultuWorkerLogPath(c *Config, i int) string {
	return filepath.Join("/var/log/virlink", fmt.Sprintf("%s-w%d-openvpn.log", tunnelInstanceName(c), i))
}

func openvpnMultuWorkerPIDPath(c *Config, i int) string {
	return filepath.Join("/var/run/virlink", fmt.Sprintf("%s-w%d-openvpn.pid", tunnelInstanceName(c), i))
}

func (t *OpenvpnMultuTunnel) Down() error {
	t.doClean()
	logOK("openvpnmultu torn down")
	return nil
}

func (t *OpenvpnMultuTunnel) doClean() {
	if t.cfg != nil {
		openvpnMultuPreclean(t.cfg)
	}
	peer := t.PeerIP()
	nlRouteDel(peer)

	if t.loAddr != "" {
		if lo, err := netlink.LinkByName("lo"); err == nil {
			if addr, err := netlink.ParseAddr(t.loAddr); err == nil {
				_ = netlink.AddrDel(lo, addr)
			}
		}
		t.loAddr = ""
	}

	for i := range t.workers {
		t.stopWorker(&t.workers[i])
	}
	t.workers = nil

	if t.lockFd != nil {
		releaseTunnelLock(t.lockFd)
		t.lockFd = nil
	}
	if t.runtimeDir != "" {
		_ = os.RemoveAll(t.runtimeDir)
		t.runtimeDir = ""
	}
	restoreTunnelTuning()
}

func (t *OpenvpnMultuTunnel) stopWorker(w *openvpnMultuWorker) {
	if w == nil {
		return
	}
	if w.cmd != nil && w.cmd.Process != nil {
		_ = w.cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() {
			_ = w.cmd.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = w.cmd.Process.Kill()
		}
	}
	w.cmd = nil
	if w.pidPath != "" {
		openvpnKillStalePID(w.pidPath)
	}
	if w.dev != "" {
		delMSS(w.dev)
		nlDown(w.dev)
	}
}

func (t *OpenvpnMultuTunnel) Status() {
	fmt.Printf("  overlay: %s  peer: %s\n", t.OverlayIP(), t.PeerIP())
	fmt.Printf("  workers: %d  ports: %s  pki: %s\n",
		t.cfg.OpenVPNMultu.Workers, openvpnMultuPortRange(t.cfg), t.cfg.OpenVPNMultu.PKIDir)
	for _, w := range t.workers {
		state := "down"
		if w.cmd != nil && w.cmd.Process != nil && openvpnProcessAlive(w.cmd) {
			state = fmt.Sprintf("pid=%d", w.cmd.Process.Pid)
		}
		fmt.Printf("  %s: %s\n", w.dev, state)
	}
	if t.loAddr != "" {
		fmt.Printf("  lo addr: %s\n", t.loAddr)
	}
}
