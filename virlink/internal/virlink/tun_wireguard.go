// tun_wireguard.go — WireGuard site-to-site via wireguard-tools (wg + ip).
//
// virlink reads a standard wg-quick-style conf, creates the kernel interface,
// applies keys/peers, assigns the overlay address, and tears down on exit.
package virlink

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
)

const wireguardSubnet = "10.20.10.0/30"

type wgConfSection struct {
	kv map[string]string
}

type wgConf struct {
	iface wgConfSection
	peer  wgConfSection
}

type WireGuardTunnel struct {
	cfg    *Config
	lockFd *os.File
}

func (t *WireGuardTunnel) DevName() string {
	if t.cfg.WireGuard.Dev != "" {
		return t.cfg.WireGuard.Dev
	}
	return "wg-virlink0"
}

func (t *WireGuardTunnel) OverlayIP() string { return overlayAddr(t.cfg, wireguardSubnet) }
func (t *WireGuardTunnel) PeerIP() string    { return peerAddr(t.cfg, wireguardSubnet) }

func (t *WireGuardTunnel) Up() error {
	c := t.cfg
	wg := c.WireGuard
	if wg.Config == "" {
		return fmt.Errorf("[wireguard] config path is required")
	}
	if _, err := os.Stat(wg.Config); err != nil {
		return fmt.Errorf("[wireguard] config %q: %w", wg.Config, err)
	}
	if _, err := exec.LookPath("wg"); err != nil {
		return fmt.Errorf("wg not found — install: apt install wireguard-tools")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		return fmt.Errorf("ip not found — install: apt install iproute2")
	}

	dev := t.DevName()
	addr := t.OverlayIP()
	peer := t.PeerIP()
	port := c.Transport.Port
	if port == 0 {
		port = 51820
	}

	header("wireguard / " + c.Mode)
	applyPerfFromConfig(c)
	step("cleanup...")
	t.doClean()

	var err error
	t.lockFd, err = acquireTunnelLock(dev)
	if err != nil {
		return err
	}

	conf, err := parseWireGuardConf(wg.Config)
	if err != nil {
		return fmt.Errorf("[wireguard] parse %q: %w", wg.Config, err)
	}

	step("creating WireGuard interface " + dev + "...")
	if err := applyWireGuardConf(dev, conf, c.Tunnel.MTU); err != nil {
		t.doClean()
		return err
	}

	step(fmt.Sprintf("tuning (%s)...", tuningModeLabel(c)))
	applyTunnelTuning(c, dev)
	addMSS(dev)

	if out, err := runOut("wg", "show", dev); err == nil && out != "" {
		logOK("wg show " + dev)
		for _, line := range strings.Split(out, "\n") {
			if strings.TrimSpace(line) != "" {
				logDebug("  " + line)
			}
		}
	}

	logOK(fmt.Sprintf("wireguard up  dev=%s", dev))
	logOK(fmt.Sprintf("overlay %s  peer %s", addr, peer))

	done(dev, addr, peer,
		fmt.Sprintf("transport : WireGuard UDP :%d", port),
		"config    : "+wg.Config,
		"test      : ping -c3 "+peer,
	)
	return nil
}

func (t *WireGuardTunnel) Down() error {
	t.doClean()
	logOK("wireguard tunnel torn down")
	return nil
}

func (t *WireGuardTunnel) doClean() {
	if t.lockFd != nil {
		releaseTunnelLock(t.lockFd)
		t.lockFd = nil
	}
	restoreTunnelTuning()
	delMSS(t.DevName())
	nlDown(t.DevName())
}

func (t *WireGuardTunnel) Status() {
	dev := t.DevName()
	if l, err := netlink.LinkByName(dev); err == nil {
		fmt.Printf("  %s: flags=%v\n", l.Attrs().Name, l.Attrs().Flags)
	}
	if out, err := runOut("wg", "show", dev); err == nil {
		fmt.Printf("  wg show:\n")
		for _, line := range strings.Split(out, "\n") {
			fmt.Printf("    %s\n", line)
		}
	}
	fmt.Printf("  config: %s\n", t.cfg.WireGuard.Config)
}

func parseWireGuardConf(path string) (*wgConf, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	conf := &wgConf{
		iface: wgConfSection{kv: map[string]string{}},
		peer:  wgConfSection{kv: map[string]string{}},
	}
	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		switch section {
		case "interface":
			conf.iface.kv[strings.ToLower(key)] = val
		case "peer":
			conf.peer.kv[strings.ToLower(key)] = val
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if conf.iface.kv["privatekey"] == "" {
		return nil, fmt.Errorf("missing [Interface] PrivateKey")
	}
	if conf.peer.kv["publickey"] == "" {
		return nil, fmt.Errorf("missing [Peer] PublicKey")
	}
	return conf, nil
}

func applyWireGuardConf(dev string, conf *wgConf, mtu int) error {
	nlDown(dev)

	if err := run("ip", "link", "add", dev, "type", "wireguard"); err != nil {
		return fmt.Errorf("ip link add: %w", err)
	}

	privKey := conf.iface.kv["privatekey"]
	if err := wgSetKey(dev, "private-key", privKey); err != nil {
		nlDown(dev)
		return err
	}

	if lp := conf.iface.kv["listenport"]; lp != "" {
		if err := run("wg", "set", dev, "listen-port", lp); err != nil {
			nlDown(dev)
			return fmt.Errorf("wg listen-port: %w", err)
		}
	}

	pubKey := conf.peer.kv["publickey"]
	args := []string{"set", dev, "peer", pubKey}
	if ips := conf.peer.kv["allowedips"]; ips != "" {
		args = append(args, "allowed-ips", ips)
	}
	if ep := conf.peer.kv["endpoint"]; ep != "" {
		args = append(args, "endpoint", ep)
	}
	if ka := conf.peer.kv["persistentkeepalive"]; ka != "" {
		args = append(args, "persistent-keepalive", ka)
	}
	if err := run("wg", args...); err != nil {
		nlDown(dev)
		return fmt.Errorf("wg peer: %w", err)
	}

	if addr := conf.iface.kv["address"]; addr != "" {
		// wg-quick conf may list multiple comma-separated addresses
		for _, a := range strings.Split(addr, ",") {
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			if err := run("ip", "addr", "add", a, "dev", dev); err != nil {
				nlDown(dev)
				return fmt.Errorf("ip addr add %s: %w", a, err)
			}
		}
	}

	l, err := netlink.LinkByName(dev)
	if err != nil {
		nlDown(dev)
		return fmt.Errorf("link %s: %w", dev, err)
	}
	if mtu > 0 {
		_ = netlink.LinkSetMTU(l, mtu)
	}
	if err := netlink.LinkSetUp(l); err != nil {
		nlDown(dev)
		return fmt.Errorf("link up %s: %w", dev, err)
	}

	// brief wait for handshake on client
	if conf.peer.kv["endpoint"] != "" {
		time.Sleep(300 * time.Millisecond)
	}
	return nil
}

func wgSetKey(dev, keyType, value string) error {
	cmd := exec.Command("wg", "set", dev, keyType, "/dev/stdin")
	cmd.Stdin = strings.NewReader(value + "\n")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("wg %s: %s", keyType, msg)
		}
		return fmt.Errorf("wg %s: %w", keyType, err)
	}
	return nil
}
