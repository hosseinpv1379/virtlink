// tun_ikev2.go — IKEv2 site-to-site via strongSwan (swanctl + xfrm interface).
//
// Route-based IPsec: overlay CIDR in traffic selectors, xfrm dev carries local overlay IP.
package virlink

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
)

const ikev2Subnet = "10.20.60.0/24"

const (
	ikev2ConnDefault  = "virlink"
	ikev2ChildDefault = "net"
)

type Ikev2Tunnel struct {
	cfg      *Config
	lockFd   *os.File
	swanctl  string
	conn     string
	child    string
	ifID     int
	overlay  string
	peerPlain string
}

func (t *Ikev2Tunnel) DevName() string {
	if t.cfg.Ikev2.Dev != "" {
		return t.cfg.Ikev2.Dev
	}
	return "ipsec0"
}

func (t *Ikev2Tunnel) OverlayIP() string {
	if t.overlay != "" {
		return t.overlay
	}
	return overlayAddr(t.cfg, ikev2Subnet)
}

func (t *Ikev2Tunnel) PeerIP() string {
	if t.peerPlain != "" {
		return t.peerPlain
	}
	return peerAddr(t.cfg, ikev2Subnet)
}

func (t *Ikev2Tunnel) Up() error {
	c := t.cfg
	ik := c.Ikev2

	t.swanctl = ik.SwanctlDir
	if t.swanctl == "" {
		return fmt.Errorf("[ikev2] swanctl_dir is required")
	}
	if _, err := os.Stat(t.swanctl); err != nil {
		return fmt.Errorf("[ikev2] swanctl dir %q: %w", t.swanctl, err)
	}
	if _, err := exec.LookPath("swanctl"); err != nil {
		return fmt.Errorf("swanctl not found — install: apt install strongswan-swanctl strongswan")
	}

	t.conn = ik.Conn
	if t.conn == "" {
		t.conn = ikev2ConnDefault
	}
	t.child = ik.Child
	if t.child == "" {
		t.child = ikev2ChildDefault
	}
	t.ifID = ik.IfID
	if t.ifID <= 0 {
		t.ifID = ikev2DefaultIfID(c.Tunnel.Name)
	}
	t.overlay = overlayAddr(c, ikev2Subnet)
	t.peerPlain = peerAddr(c, ikev2Subnet)

	dev := t.DevName()
	header("ikev2 / " + c.Mode)
	logInfo(fmt.Sprintf("strongSwan IKEv2  conn=%s  child=%s  if_id=%d", t.conn, t.child, t.ifID))

	applyPerfFromConfig(c)
	step("cleanup...")
	t.doClean()

	var err error
	t.lockFd, err = acquireTunnelLock(dev)
	if err != nil {
		return err
	}

	step("loading kernel modules (xfrm, esp)...")
	for _, mod := range []string{"xfrm_user", "xfrm_interface", "esp4", "esp6"} {
		_ = run("modprobe", mod)
	}

	step("starting strongSwan charon...")
	if err := ensureCharonRunning(); err != nil {
		t.doClean()
		return err
	}

	step("loading swanctl credentials and connections...")
	if err := swanctlLoadAll(t.swanctl); err != nil {
		t.doClean()
		return err
	}

	step("creating xfrm interface " + dev + "...")
	if err := t.setupXfrmDev(dev); err != nil {
		t.doClean()
		return err
	}

	step(fmt.Sprintf("tuning (%s)...", tuningModeLabel(c)))
	applyTunnelTuning(c, dev)
	addMSS(dev)

	logIkev2Status(t.conn, t.child, c.Mode)

	step("waiting for IKEv2 / IPsec SA...")
	if c.Mode == "client" {
		if err := swanctlInitiate(t.conn, t.child, 45*time.Second); err != nil {
			t.doClean()
			return err
		}
	}
	if err := waitForIkev2SA(t.conn, 45*time.Second); err != nil {
		if c.Mode == "client" {
			t.doClean()
			return err
		}
		logWarn("no IKE SA yet — start the client; ensure UDP 500/4500 open on both hosts + cloud firewall")
	} else {
		logOK("IKEv2 SA established")
	}

	addr := t.OverlayIP()
	peer := t.PeerIP()
	logOK(fmt.Sprintf("ikev2 up  dev=%s  overlay %s  peer %s", dev, addr, peer))
	done(dev, addr, peer,
		"transport : IKEv2 UDP 500 / NAT-T 4500",
		"swanctl   : "+t.swanctl,
		"status    : swanctl --list-sas --ike "+t.conn,
		"test      : ping -c3 "+peer,
	)
	return nil
}

func (t *Ikev2Tunnel) setupXfrmDev(dev string) error {
	nlDown(dev)
	if err := run("ip", "link", "add", dev, "type", "xfrm", "if_id", strconv.Itoa(t.ifID)); err != nil {
		return fmt.Errorf("ip link add xfrm: %w (try: modprobe xfrm_interface)", err)
	}
	overlay := t.OverlayIP()
	if err := run("ip", "addr", "add", overlay, "dev", dev); err != nil {
		nlDown(dev)
		return fmt.Errorf("ip addr add %s: %w", overlay, err)
	}
	l, err := netlink.LinkByName(dev)
	if err != nil {
		nlDown(dev)
		return err
	}
	if mtu := t.cfg.Tunnel.MTU; mtu > 0 {
		_ = netlink.LinkSetMTU(l, mtu)
	}
	if err := netlink.LinkSetUp(l); err != nil {
		nlDown(dev)
		return fmt.Errorf("link up %s: %w", dev, err)
	}
	logOK("address " + overlay + " on " + dev)
	return nil
}

func (t *Ikev2Tunnel) Down() error {
	t.doClean()
	logOK("ikev2 tunnel torn down")
	return nil
}

func (t *Ikev2Tunnel) doClean() {
	dev := t.DevName()
	if t.conn != "" {
		_ = run("swanctl", "--terminate", "--ike", t.conn)
	}
	if t.swanctl != "" {
		_ = run("swanctl", "--unload-conns")
	}
	if t.lockFd != nil {
		releaseTunnelLock(t.lockFd)
		t.lockFd = nil
	}
	restoreTunnelTuning()
	delMSS(dev)
	nlDown(dev)
}

func (t *Ikev2Tunnel) Status() {
	dev := t.DevName()
	if l, err := netlink.LinkByName(dev); err == nil {
		fmt.Printf("  %s: flags=%v\n", l.Attrs().Name, l.Attrs().Flags)
	}
	conn := t.conn
	if conn == "" {
		conn = ikev2ConnDefault
	}
	logIkev2Status(conn, t.child, t.cfg.Mode)
	fmt.Printf("  swanctl: %s\n", t.cfg.Ikev2.SwanctlDir)
}

func ikev2DefaultIfID(name string) int {
	if name == "" {
		return 42
	}
	var h uint32
	for i := 0; i < len(name); i++ {
		h = h*31 + uint32(name[i])
	}
	id := int(h%60000) + 1
	if id < 2 {
		id = 42
	}
	return id
}

func ensureCharonRunning() error {
	for _, svc := range []string{"strongswan", "strongswan-starter", "charon-systemd"} {
		_ = run("systemctl", "start", svc)
	}
	time.Sleep(500 * time.Millisecond)
	if out, err := runOut("swanctl", "--version"); err == nil {
		logInfo(strings.TrimSpace(out))
		return nil
	}
	return fmt.Errorf("charon not responding — run: systemctl start strongswan && swanctl --version")
}

func swanctlLoadAll(dir string) error {
	for _, sub := range []string{"--load-authorities", "--load-creds", "--load-conns", "--load-pools"} {
		if err := run("swanctl", sub, "--file", dir); err != nil {
			return fmt.Errorf("swanctl %s: %w", sub, err)
		}
	}
	return nil
}

func swanctlInitiate(conn, child string, timeout time.Duration) error {
	sec := int(timeout.Seconds())
	if sec < 1 {
		sec = 30
	}
	if err := run("swanctl", "--initiate", "--ike", conn, "--child", child, "--timeout", strconv.Itoa(sec)); err != nil {
		return fmt.Errorf("swanctl initiate: %w (is server up? UDP 500/4500 open?)", err)
	}
	return nil
}

func waitForIkev2SA(conn string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ikev2SAEstablished(conn) {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	out, _ := runOut("swanctl", "--list-sas", "--ike", conn)
	return fmt.Errorf("IKEv2 SA timeout (%s)\n%s", timeout.Round(time.Second), out)
}

func ikev2SAEstablished(conn string) bool {
	out, err := runOut("swanctl", "--list-sas", "--ike", conn)
	if err != nil {
		return false
	}
	return strings.Contains(out, "ESTABLISHED")
}

func logIkev2Status(conn, child, mode string) {
	if out, err := runOut("swanctl", "--list-conns", "--ike", conn); err == nil && strings.TrimSpace(out) != "" {
		logInfo("── swanctl --list-conns ──")
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				logInfo("  " + line)
			}
		}
	}
	if out, err := runOut("swanctl", "--list-sas", "--ike", conn); err == nil && strings.TrimSpace(out) != "" {
		logInfo("── swanctl --list-sas ──")
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				logInfo("  " + line)
			}
		}
	}
	if ikev2SAEstablished(conn) {
		logOK("IKE SA: ESTABLISHED")
	} else if mode == "server" {
		logInfo("  no IKE SA yet — start the client tunnel")
	} else {
		logWarn("  no IKE SA yet — check server, PKI, firewall UDP 500/4500")
	}
	_ = child
}

// ikev2SwanctlDir returns default swanctl path for tunnel name.
func ikev2SwanctlDir(name string) string {
	return filepath.Join("/opt/virlink/pki", name, "swanctl")
}
