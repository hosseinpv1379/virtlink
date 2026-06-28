// tun_amneziawg.go — AmneziaWG site-to-site (obfuscated WireGuard via awg + amneziawg module).
package virlink

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
)

const amneziawgSubnet = "10.20.11.0/30"

type AmneziaWGTunnel struct {
	cfg         *Config
	lockFd      *os.File
	overlayCIDR string
	peerPlain   string
}

func (t *AmneziaWGTunnel) DevName() string {
	if t.cfg.AmneziaWG.Dev != "" {
		return t.cfg.AmneziaWG.Dev
	}
	return "awg-virlink0"
}

func (t *AmneziaWGTunnel) OverlayIP() string {
	if t.overlayCIDR != "" {
		return t.overlayCIDR
	}
	return overlayAddr(t.cfg, amneziawgSubnet)
}

func (t *AmneziaWGTunnel) PeerIP() string {
	if t.peerPlain != "" {
		return t.peerPlain
	}
	return peerAddr(t.cfg, amneziawgSubnet)
}

func (t *AmneziaWGTunnel) Up() error {
	c := t.cfg
	awg := c.AmneziaWG
	if awg.Config == "" {
		return fmt.Errorf("[amneziawg] config path is required")
	}
	if _, err := os.Stat(awg.Config); err != nil {
		return fmt.Errorf("[amneziawg] config %q: %w", awg.Config, err)
	}
	if _, err := exec.LookPath("awg"); err != nil {
		return fmt.Errorf("awg not found — install AmneziaWG: add-apt-repository ppa:amnezia/ppa && apt install amneziawg")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		return fmt.Errorf("ip not found — install: apt install iproute2")
	}

	dev := t.DevName()
	port := c.Transport.Port
	if port == 0 {
		port = 51820
	}

	header("amneziawg / " + c.Mode)
	logInfo("obfuscated WireGuard — DPI-resistant UDP (Jc/S/H params in conf)")
	applyPerfFromConfig(c)
	step("cleanup...")
	t.doClean()

	var err error
	t.lockFd, err = acquireTunnelLock(dev)
	if err != nil {
		return err
	}

	step("loading amneziawg kernel module...")
	_ = run("modprobe", "amneziawg")

	conf, err := parseWireGuardConf(awg.Config)
	if err != nil {
		return fmt.Errorf("[amneziawg] parse %q: %w", awg.Config, err)
	}
	t.overlayCIDR = firstWireGuardAddress(conf)
	t.peerPlain = wireguardPeerIPSubnet(conf, c, amneziawgSubnet)

	if ep := conf.peer.kv["endpoint"]; ep != "" && c.Mode == "client" {
		host, epPort, splitErr := net.SplitHostPort(ep)
		if splitErr == nil {
			if host != c.RemoteIP && net.ParseIP(host) != nil {
				logWarn(fmt.Sprintf("Endpoint %s ≠ remote_ip %s in toml — using Endpoint from awg conf", host, c.RemoteIP))
			}
			if p, _ := strconv.Atoi(epPort); p > 0 && p != port {
				logWarn(fmt.Sprintf("Endpoint port %d ≠ transport.port %d in toml — awg conf port wins", p, port))
			}
		}
	}

	step("creating AmneziaWG interface " + dev + "...")
	if err := applyAmneziaWGConf(dev, awg.Config, conf, c.Tunnel.MTU); err != nil {
		t.doClean()
		return err
	}

	if c.Mode == "client" {
		t.applyClientRpFilter()
	}

	step(fmt.Sprintf("tuning (%s)...", tuningModeLabel(c)))
	applyTunnelTuning(c, dev)
	addMSS(dev)

	logWireGuardStatus(dev, c.Mode, "awg")

	step("waiting for AmneziaWG handshake...")
	if c.Mode == "client" {
		if err := waitForWireGuardHandshake(dev, "awg", 45*time.Second); err != nil {
			t.doClean()
			return err
		}
	} else if _, ok := wireguardLatestHandshake(dev, "awg"); !ok {
		logInfo("server listening — handshake will complete when the client starts")
		logInfo("ensure UDP listen-port is open in firewall (Hetzner + iptables/ufw)")
	} else {
		logOK("handshake already active")
	}

	addr := t.OverlayIP()
	peer := t.PeerIP()
	if _, ok := wireguardLatestHandshake(dev, "awg"); ok {
		logOK(fmt.Sprintf("amneziawg up  dev=%s  handshake=ok", dev))
	} else {
		logOK(fmt.Sprintf("amneziawg up  dev=%s  handshake=pending (start client)", dev))
	}
	logOK(fmt.Sprintf("overlay %s  peer %s", addr, peer))

	done(dev, addr, peer,
		"transport : AmneziaWG UDP (obfuscated WireGuard)",
		"config    : "+awg.Config,
		"status    : awg show "+dev,
		"test      : ping -c3 "+peer,
	)
	return nil
}

func applyAmneziaWGConf(dev, confPath string, conf *wgConf, mtu int) error {
	nlDown(dev)

	if err := run("ip", "link", "add", dev, "type", "amneziawg"); err != nil {
		return fmt.Errorf("ip link add: %w (try: modprobe amneziawg; install PPA amnezia/ppa)", err)
	}

	kernelConf, cleanup, err := awgKernelConfFile(confPath, conf)
	if err != nil {
		nlDown(dev)
		return err
	}
	defer cleanup()

	logAwgObfsParams(conf)
	if err := run("awg", "setconf", dev, kernelConf); err != nil {
		nlDown(dev)
		return fmt.Errorf("awg setconf: %w (check Jc/Jmin/Jmax/S/H in %s)", err, confPath)
	}
	logOK("awg setconf applied (keys, peer, obfuscation — atomic)")

	if addr := conf.iface.kv["address"]; addr != "" {
		for _, a := range strings.Split(addr, ",") {
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			if err := run("ip", "addr", "add", a, "dev", dev); err != nil {
				nlDown(dev)
				return fmt.Errorf("ip addr add %s: %w", a, err)
			}
			logOK("address " + a)
		}
	}

	if lp := conf.iface.kv["listenport"]; lp != "" {
		logOK("listen-port " + lp + " UDP")
	}
	if ep := conf.peer.kv["endpoint"]; ep != "" {
		logOK("peer endpoint " + ep)
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
	return nil
}

// awgKernelConfFile builds a kernel-only awg config (no Address/DNS/PostUp).
// Obfuscation params must be applied atomically — separate awg set jc/jmin calls
// break validation (jc alone auto-bumps jmax when jmin=jmax=0).
func awgKernelConfFile(confPath string, conf *wgConf) (path string, cleanup func(), err error) {
	cleanup = func() {}
	if _, lookErr := exec.LookPath("awg-quick"); lookErr == nil {
		out, stripErr := runOut("awg-quick", "strip", confPath)
		if stripErr == nil && strings.TrimSpace(out) != "" {
			path, cleanup, err = writeTempAwgConf(out)
			if err == nil {
				logDebug("awg kernel conf via awg-quick strip → " + path)
				return path, cleanup, nil
			}
		}
		logDebug("awg-quick strip failed, using manual kernel conf builder")
	}
	var b strings.Builder
	writeAwgKernelConf(&b, conf)
	path, cleanup, err = writeTempAwgConf(b.String())
	if err == nil {
		logDebug("awg kernel conf (manual strip) → " + path)
	}
	return path, cleanup, err
}

func writeTempAwgConf(body string) (path string, cleanup func(), err error) {
	cleanup = func() {}
	f, err := os.CreateTemp("", "awg-setconf-*.conf")
	if err != nil {
		return "", cleanup, err
	}
	path = f.Name()
	cleanup = func() { _ = os.Remove(path) }
	if _, err := f.WriteString(body); err != nil {
		cleanup()
		return "", func() {}, err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	_ = os.Chmod(path, 0600)
	return path, cleanup, nil
}

func writeAwgKernelConf(w *strings.Builder, conf *wgConf) {
	w.WriteString("[Interface]\n")
	fmt.Fprintf(w, "PrivateKey = %s\n", conf.iface.kv["privatekey"])
	if v := conf.iface.kv["listenport"]; v != "" {
		fmt.Fprintf(w, "ListenPort = %s\n", v)
	}
	for _, p := range []struct{ label, key string }{
		{"Jc", "jc"}, {"Jmin", "jmin"}, {"Jmax", "jmax"},
		{"S1", "s1"}, {"S2", "s2"}, {"S3", "s3"}, {"S4", "s4"},
		{"H1", "h1"}, {"H2", "h2"}, {"H3", "h3"}, {"H4", "h4"},
	} {
		if v := conf.iface.kv[p.key]; v != "" {
			fmt.Fprintf(w, "%s = %s\n", p.label, v)
		}
	}
	w.WriteString("\n[Peer]\n")
	fmt.Fprintf(w, "PublicKey = %s\n", conf.peer.kv["publickey"])
	if v := conf.peer.kv["allowedips"]; v != "" {
		fmt.Fprintf(w, "AllowedIPs = %s\n", v)
	}
	if v := conf.peer.kv["endpoint"]; v != "" {
		fmt.Fprintf(w, "Endpoint = %s\n", v)
	}
	if v := conf.peer.kv["persistentkeepalive"]; v != "" {
		fmt.Fprintf(w, "PersistentKeepalive = %s\n", v)
	}
}

func logAwgObfsParams(conf *wgConf) {
	parts := []string{}
	for _, p := range []struct{ label, key string }{
		{"Jc", "jc"}, {"Jmin", "jmin"}, {"Jmax", "jmax"},
		{"S1", "s1"}, {"S2", "s2"}, {"H1", "h1"}, {"H2", "h2"}, {"H3", "h3"}, {"H4", "h4"},
	} {
		if v := conf.iface.kv[p.key]; v != "" {
			parts = append(parts, p.label+"="+v)
		}
	}
	if len(parts) > 0 {
		logInfo("awg obfuscation: " + strings.Join(parts, " "))
	}
}

func (t *AmneziaWGTunnel) Down() error {
	t.doClean()
	logOK("amneziawg tunnel torn down")
	return nil
}

func (t *AmneziaWGTunnel) doClean() {
	t.restoreClientRpFilter()
	if t.lockFd != nil {
		releaseTunnelLock(t.lockFd)
		t.lockFd = nil
	}
	restoreTunnelTuning()
	delMSS(t.DevName())
	nlDown(t.DevName())
}

func (t *AmneziaWGTunnel) applyClientRpFilter() {
	for _, k := range []string{"net.ipv4.conf.default.rp_filter", "net.ipv4.conf.all.rp_filter"} {
		if err := nlSysctl(k, "2"); err != nil {
			logWarn(fmt.Sprintf("rp_filter %s: %v", k, err))
		}
	}
	if dev := t.DevName(); dev != "" {
		k := "net.ipv4.conf." + dev + ".rp_filter"
		if err := nlSysctl(k, "2"); err != nil {
			logWarn(fmt.Sprintf("rp_filter %s: %v", k, err))
		}
	}
}

func (t *AmneziaWGTunnel) restoreClientRpFilter() {}

func (t *AmneziaWGTunnel) Status() {
	dev := t.DevName()
	if l, err := netlink.LinkByName(dev); err == nil {
		fmt.Printf("  %s: flags=%v\n", l.Attrs().Name, l.Attrs().Flags)
	}
	logWireGuardStatus(dev, t.cfg.Mode, "awg")
	fmt.Printf("  config: %s\n", t.cfg.AmneziaWG.Config)
}
