// tun_amneziawg.go — AmneziaWG site-to-site (obfuscated WireGuard via awg + amneziawg module).
package amneziawg

import (
	"virlink/internal/config"
	"virlink/internal/core"
	"virlink/internal/platform"
	"virlink/internal/protocol/wireguard"
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
	cfg         *config.Config
	lockFd      *os.File
	overlayCIDR string
	peerPlain   string
}

func (t *AmneziaWGTunnel) DevName() string {
	if t.cfg.AmneziaWG.Dev != "" {
		return t.cfg.AmneziaWG.Dev
	}
	return platform.TunnelDevName(t.cfg, "awg-virlink0")
}

func (t *AmneziaWGTunnel) OverlayIP() string {
	if t.overlayCIDR != "" {
		return t.overlayCIDR
	}
	return core.OverlayAddr(t.cfg, amneziawgSubnet)
}

func (t *AmneziaWGTunnel) PeerIP() string {
	if t.peerPlain != "" {
		return t.peerPlain
	}
	return core.PeerAddr(t.cfg, amneziawgSubnet)
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

	platform.Header("amneziawg / " + c.Mode)
	platform.LogInfo("obfuscated WireGuard — DPI-resistant UDP (Jc/S/H params in conf)")
	platform.ApplyPerfFromConfig(c)
	platform.Step("cleanup...")
	t.doClean()

	var err error
	t.lockFd, err = platform.AcquireTunnelLock(dev)
	if err != nil {
		return err
	}

	platform.Step("loading amneziawg kernel module...")
	_ = platform.Run("modprobe", "amneziawg")

	conf, err := wireguard.ParseWireGuardConf(awg.Config)
	if err != nil {
		return fmt.Errorf("[amneziawg] parse %q: %w", awg.Config, err)
	}
	t.overlayCIDR = wireguard.FirstWireGuardAddress(conf)
	t.peerPlain = wireguard.WireguardPeerIPSubnet(conf, c, amneziawgSubnet)

	if ep := conf.Peer.Kv["endpoint"]; ep != "" && c.Mode == "client" {
		host, epPort, splitErr := net.SplitHostPort(ep)
		if splitErr == nil {
			if host != c.RemoteIP && net.ParseIP(host) != nil {
				platform.LogWarn(fmt.Sprintf("Endpoint %s ≠ remote_ip %s in toml — using Endpoint from awg conf", host, c.RemoteIP))
			}
			if p, _ := strconv.Atoi(epPort); p > 0 && p != port {
				platform.LogWarn(fmt.Sprintf("Endpoint port %d ≠ transport.port %d in toml — awg conf port wins", p, port))
			}
		}
	}

	platform.Step("creating AmneziaWG interface " + dev + "...")
	if err := applyAmneziaWGConf(dev, awg.Config, conf, c.Tunnel.MTU); err != nil {
		t.doClean()
		return err
	}

	if c.Mode == "client" {
		t.applyClientRpFilter()
	}

	platform.Step(fmt.Sprintf("tuning (%s)...", platform.TuningModeLabel(c)))
	platform.ApplyTunnelTuning(c, dev)
	platform.AddMSS(c, dev)

	wireguard.LogWireGuardStatus(dev, c.Mode, "awg")

	platform.Step("waiting for AmneziaWG handshake...")
	if c.Mode == "client" {
		if err := wireguard.WaitForWireGuardHandshake(dev, "awg", 45*time.Second); err != nil {
			t.doClean()
			return err
		}
	} else if _, ok := wireguard.WireguardLatestHandshake(dev, "awg"); !ok {
		platform.LogInfo("server listening — handshake will complete when the client starts")
		platform.LogInfo("ensure UDP listen-port is open in firewall (Hetzner + iptables/ufw)")
	} else {
		platform.LogOK("handshake already active")
	}

	addr := t.OverlayIP()
	peer := t.PeerIP()
	if _, ok := wireguard.WireguardLatestHandshake(dev, "awg"); ok {
		platform.LogOK(fmt.Sprintf("amneziawg up  dev=%s  handshake=ok", dev))
	} else {
		platform.LogOK(fmt.Sprintf("amneziawg up  dev=%s  handshake=pending (start client)", dev))
	}
	platform.LogOK(fmt.Sprintf("overlay %s  peer %s", addr, peer))

	platform.Done(dev, addr, peer,
		"transport : AmneziaWG UDP (obfuscated WireGuard)",
		"config    : "+awg.Config,
		"status    : awg show "+dev,
		"test      : ping -c3 "+peer,
	)
	return nil
}

func applyAmneziaWGConf(dev, confPath string, conf *wireguard.WgConf, mtu int) error {
	platform.NlDown(dev)

	if err := platform.Run("ip", "link", "add", dev, "type", "amneziawg"); err != nil {
		return fmt.Errorf("ip link add: %w (platform.Try: modprobe amneziawg; install PPA amnezia/ppa)", err)
	}

	kernelConf, cleanup, err := awgKernelConfFile(confPath, conf)
	if err != nil {
		platform.NlDown(dev)
		return err
	}
	defer cleanup()

	logAwgObfsParams(conf)
	if err := platform.Run("awg", "setconf", dev, kernelConf); err != nil {
		platform.NlDown(dev)
		return fmt.Errorf("awg setconf: %w (check Jc/Jmin/Jmax/S/H in %s)", err, confPath)
	}
	platform.LogOK("awg setconf applied (keys, peer, obfuscation — atomic)")

	if addr := conf.Iface.Kv["address"]; addr != "" {
		for _, a := range strings.Split(addr, ",") {
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			if err := platform.Run("ip", "addr", "add", a, "dev", dev); err != nil {
				platform.NlDown(dev)
				return fmt.Errorf("ip addr add %s: %w", a, err)
			}
			platform.LogOK("address " + a)
		}
	}

	if lp := conf.Iface.Kv["listenport"]; lp != "" {
		platform.LogOK("listen-port " + lp + " UDP")
	}
	if ep := conf.Peer.Kv["endpoint"]; ep != "" {
		platform.LogOK("peer endpoint " + ep)
	}

	l, err := netlink.LinkByName(dev)
	if err != nil {
		platform.NlDown(dev)
		return fmt.Errorf("link %s: %w", dev, err)
	}
	if mtu > 0 {
		_ = netlink.LinkSetMTU(l, mtu)
	}
	if err := netlink.LinkSetUp(l); err != nil {
		platform.NlDown(dev)
		return fmt.Errorf("link up %s: %w", dev, err)
	}
	return nil
}

// awgKernelConfFile builds a kernel-only awg config (no Address/DNS/PostUp).
// Obfuscation params must be applied atomically — separate awg set jc/jmin calls
// break validation (jc alone auto-bumps jmax when jmin=jmax=0).
func awgKernelConfFile(confPath string, conf *wireguard.WgConf) (path string, cleanup func(), err error) {
	cleanup = func() {}
	if _, lookErr := exec.LookPath("awg-quick"); lookErr == nil {
		out, stripErr := platform.RunOut("awg-quick", "strip", confPath)
		if stripErr == nil && strings.TrimSpace(out) != "" {
			path, cleanup, err = writeTempAwWgConf(out)
			if err == nil {
				platform.LogDebug("awg kernel conf via awg-quick strip → " + path)
				return path, cleanup, nil
			}
		}
		platform.LogDebug("awg-quick strip failed, using manual kernel conf builder")
	}
	var b strings.Builder
	writeAwgKernelConf(&b, conf)
	path, cleanup, err = writeTempAwWgConf(b.String())
	if err == nil {
		platform.LogDebug("awg kernel conf (manual strip) → " + path)
	}
	return path, cleanup, err
}

func writeTempAwWgConf(body string) (path string, cleanup func(), err error) {
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

func writeAwgKernelConf(w *strings.Builder, conf *wireguard.WgConf) {
	w.WriteString("[Interface]\n")
	fmt.Fprintf(w, "PrivateKey = %s\n", conf.Iface.Kv["privatekey"])
	if v := conf.Iface.Kv["listenport"]; v != "" {
		fmt.Fprintf(w, "ListenPort = %s\n", v)
	}
	for _, p := range []struct{ label, key string }{
		{"Jc", "jc"}, {"Jmin", "jmin"}, {"Jmax", "jmax"},
		{"S1", "s1"}, {"S2", "s2"}, {"S3", "s3"}, {"S4", "s4"},
		{"H1", "h1"}, {"H2", "h2"}, {"H3", "h3"}, {"H4", "h4"},
	} {
		if v := conf.Iface.Kv[p.key]; v != "" {
			fmt.Fprintf(w, "%s = %s\n", p.label, v)
		}
	}
	w.WriteString("\n[Peer]\n")
	fmt.Fprintf(w, "PublicKey = %s\n", conf.Peer.Kv["publickey"])
	if v := conf.Peer.Kv["allowedips"]; v != "" {
		fmt.Fprintf(w, "AllowedIPs = %s\n", v)
	}
	if v := conf.Peer.Kv["endpoint"]; v != "" {
		fmt.Fprintf(w, "Endpoint = %s\n", v)
	}
	if v := conf.Peer.Kv["persistentkeepalive"]; v != "" {
		fmt.Fprintf(w, "PersistentKeepalive = %s\n", v)
	}
}

func logAwgObfsParams(conf *wireguard.WgConf) {
	parts := []string{}
	for _, p := range []struct{ label, key string }{
		{"Jc", "jc"}, {"Jmin", "jmin"}, {"Jmax", "jmax"},
		{"S1", "s1"}, {"S2", "s2"}, {"H1", "h1"}, {"H2", "h2"}, {"H3", "h3"}, {"H4", "h4"},
	} {
		if v := conf.Iface.Kv[p.key]; v != "" {
			parts = append(parts, p.label+"="+v)
		}
	}
	if len(parts) > 0 {
		platform.LogInfo("awg obfuscation: " + strings.Join(parts, " "))
	}
}

func (t *AmneziaWGTunnel) Down() error {
	t.doClean()
	platform.LogOK("amneziawg tunnel torn down")
	return nil
}

func (t *AmneziaWGTunnel) doClean() {
	t.restoreClientRpFilter()
	if t.lockFd != nil {
		platform.ReleaseTunnelLock(t.lockFd)
		t.lockFd = nil
	}
	platform.RestoreTunnelTuning()
	platform.DelMSS(t.DevName())
	platform.NlDown(t.DevName())
}

func (t *AmneziaWGTunnel) applyClientRpFilter() {
	for _, k := range []string{"net.ipv4.conf.default.rp_filter", "net.ipv4.conf.all.rp_filter"} {
		if err := platform.NlSysctl(k, "2"); err != nil {
			platform.LogWarn(fmt.Sprintf("rp_filter %s: %v", k, err))
		}
	}
	if dev := t.DevName(); dev != "" {
		k := "net.ipv4.conf." + dev + ".rp_filter"
		if err := platform.NlSysctl(k, "2"); err != nil {
			platform.LogWarn(fmt.Sprintf("rp_filter %s: %v", k, err))
		}
	}
}

func (t *AmneziaWGTunnel) restoreClientRpFilter() {}

func (t *AmneziaWGTunnel) Status() {
	dev := t.DevName()
	if l, err := netlink.LinkByName(dev); err == nil {
		fmt.Printf("  %s: flags=%v\n", l.Attrs().Name, l.Attrs().Flags)
	}
	wireguard.LogWireGuardStatus(dev, t.cfg.Mode, "awg")
	fmt.Printf("  config: %s\n", t.cfg.AmneziaWG.Config)
}
