// tun_wireguard.go — WireGuard site-to-site via wireguard-tools (wg + ip).
//
// virlink reads a standard wg-quick-style conf, creates the kernel interface,
// applies keys/peers, assigns the overlay address, and verifies handshake.
package wireguard

import (
	"virlink/internal/platform"
	"virlink/internal/core"
	"virlink/internal/config"
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
)

const wireguardSubnet = "10.20.10.0/30"

type WgConfSection struct {
	Kv map[string]string
}

type WgConf struct {
	Iface WgConfSection
	Peer  WgConfSection
}

type WireGuardTunnel struct {
	cfg         *config.Config
	lockFd      *os.File
	overlayCIDR string // from wg conf Address (source of truth)
	peerPlain   string // peer overlay IP derived from AllowedIPs / config
}

func (t *WireGuardTunnel) DevName() string {
	if t.cfg.WireGuard.Dev != "" {
		return t.cfg.WireGuard.Dev
	}
	return platform.TunnelDevName(t.cfg, "wg-virlink0")
}

func (t *WireGuardTunnel) OverlayIP() string {
	if t.overlayCIDR != "" {
		return t.overlayCIDR
	}
	return core.OverlayAddr(t.cfg, wireguardSubnet)
}

func (t *WireGuardTunnel) PeerIP() string {
	if t.peerPlain != "" {
		return t.peerPlain
	}
	return core.PeerAddr(t.cfg, wireguardSubnet)
}

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
	port := c.Transport.Port
	if port == 0 {
		port = 51820
	}

	platform.Header("wireguard / " + c.Mode)
	platform.ApplyPerfFromConfig(c)
	platform.Step("cleanup...")
	t.doClean()

	var err error
	t.lockFd, err = platform.AcquireTunnelLock(dev)
	if err != nil {
		return err
	}

	platform.Step("loading wireguard kernel module...")
	_ = platform.Run("modprobe", "wireguard")

	conf, err := parseWireGuardConf(wg.Config)
	if err != nil {
		return fmt.Errorf("[wireguard] parse %q: %w", wg.Config, err)
	}
	t.overlayCIDR = firstWireGuardAddress(conf)
	t.peerPlain = wireguardPeerIP(conf, c)

	if ep := conf.Peer.Kv["endpoint"]; ep != "" && c.Mode == "client" {
		host, epPort, splitErr := net.SplitHostPort(ep)
		if splitErr == nil {
			if host != c.RemoteIP && net.ParseIP(host) != nil {
				platform.LogWarn(fmt.Sprintf("Endpoint %s ≠ remote_ip %s in toml — using Endpoint from wg conf", host, c.RemoteIP))
			}
			if p, _ := strconv.Atoi(epPort); p > 0 && p != port {
				platform.LogWarn(fmt.Sprintf("Endpoint port %d ≠ transport.port %d in toml — wg conf port wins", p, port))
			}
		}
	}

	platform.Step("creating WireGuard interface " + dev + "...")
	if err := applyWireGuardConf(dev, conf, c.Tunnel.MTU); err != nil {
		t.doClean()
		return err
	}

	if c.Mode == "client" {
		t.applyWireGuardClientRpFilter()
	}

	platform.Step(fmt.Sprintf("tuning (%s)...", platform.TuningModeLabel(c)))
	platform.ApplyTunnelTuning(c, dev)
	platform.AddMSS(c, dev)

	logWireGuardStatus(dev, c.Mode, "wg")

	platform.Step("waiting for WireGuard handshake...")
	if c.Mode == "client" {
		if err := waitForWireGuardHandshake(dev, "wg", 45*time.Second); err != nil {
			t.doClean()
			return err
		}
	} else if _, ok := WireguardLatestHandshake(dev, "wg"); !ok {
		platform.LogInfo("server listening — handshake will complete when the client starts")
		platform.LogInfo("ensure UDP listen-port is open in firewall (Hetzner + iptables/ufw)")
	} else {
		platform.LogOK("handshake already active")
	}

	addr := t.OverlayIP()
	peer := t.PeerIP()
	if _, ok := WireguardLatestHandshake(dev, "wg"); ok {
		platform.LogOK(fmt.Sprintf("wireguard up  dev=%s  wg-handshake=ok", dev))
	} else {
		platform.LogOK(fmt.Sprintf("wireguard up  dev=%s  wg-handshake=pending (start client)", dev))
	}
	platform.LogOK(fmt.Sprintf("overlay %s  peer %s", addr, peer))

	platform.Done(dev, addr, peer,
		fmt.Sprintf("transport : WireGuard UDP (see wg conf ListenPort / Endpoint)"),
		"config    : "+wg.Config,
		"status    : wg show "+dev,
		"test      : ping -c3 "+peer,
	)
	return nil
}

func (t *WireGuardTunnel) Down() error {
	t.doClean()
	platform.LogOK("wireguard tunnel torn down")
	return nil
}

func (t *WireGuardTunnel) doClean() {
	t.restoreWireGuardClientRpFilter()
	if t.lockFd != nil {
		platform.ReleaseTunnelLock(t.lockFd)
		t.lockFd = nil
	}
	platform.RestoreTunnelTuning()
	platform.DelMSS(t.DevName())
	platform.NlDown(t.DevName())
}

func (t *WireGuardTunnel) applyWireGuardClientRpFilter() {
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

func (t *WireGuardTunnel) restoreWireGuardClientRpFilter() {
	// best-effort restore not tracked — same as hysteria2 optional path
}

func (t *WireGuardTunnel) Status() {
	dev := t.DevName()
	if l, err := netlink.LinkByName(dev); err == nil {
		fmt.Printf("  %s: flags=%v\n", l.Attrs().Name, l.Attrs().Flags)
	}
	logWireGuardStatus(dev, t.cfg.Mode, "wg")
	fmt.Printf("  config: %s\n", t.cfg.WireGuard.Config)
}

func firstWireGuardAddress(conf *WgConf) string {
	raw := conf.Iface.Kv["address"]
	if raw == "" {
		return ""
	}
	return strings.TrimSpace(strings.Split(raw, ",")[0])
}

func wireguardPeerIP(conf *WgConf, c *config.Config) string {
	return wireguardPeerIPSubnet(conf, c, wireguardSubnet)
}

func wireguardPeerIPSubnet(conf *WgConf, c *config.Config, fallback string) string {
	if ips := conf.Peer.Kv["allowedips"]; ips != "" {
		part := strings.TrimSpace(strings.Split(ips, ",")[0])
		if ip, _, err := net.ParseCIDR(part); err == nil && ip != nil {
			return ip.String()
		}
	}
	return core.PeerAddr(c, fallback)
}

func logWireGuardStatus(dev, mode, wgCmd string) {
	out, err := platform.RunOut(wgCmd, "show", dev)
	if err != nil {
		platform.LogWarn(wgCmd + " show: " + err.Error())
		return
	}
	platform.LogInfo("── " + wgCmd + " show " + dev + " ──")
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		platform.LogInfo("  " + line)
	}
	if ts, ok := WireguardLatestHandshake(dev, wgCmd); ok {
		platform.LogOK(fmt.Sprintf("latest handshake: %s ago", time.Since(ts).Round(time.Second)))
	} else if mode == "server" {
		platform.LogInfo("  no handshake yet — start the client, ensure UDP port is open on this host")
	} else {
		platform.LogWarn("  no handshake yet — check server running, UDP port/firewall, keys, Endpoint")
	}
}

func WireguardLatestHandshake(dev, wgCmd string) (time.Time, bool) {
	out, err := platform.RunOut(wgCmd, "show", dev, "latest-handshakes")
	if err != nil {
		return time.Time{}, false
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		sec, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || sec <= 0 {
			continue
		}
		return time.Unix(sec, 0), true
	}
	return time.Time{}, false
}

func waitForWireGuardHandshake(dev, wgCmd string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, ok := WireguardLatestHandshake(dev, wgCmd); ok {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	hint := wireguardHandshakeHint("client")
	out, _ := platform.RunOut(wgCmd, "show", dev)
	return fmt.Errorf("WireGuard handshake timeout (%s)\n%s\n%s", timeout.Round(time.Second), hint, out)
}

func wireguardHandshakeHint(mode string) string {
	if mode == "server" {
		return "Server is listening — start the CLIENT tunnel. Open UDP listen-port in host + cloud firewall. Verify client has wg-client.conf from THIS server (matching keys)."
	}
	return "Check: (1) server tunnel started first  (2) UDP port open on server + cloud firewall  (3) Endpoint in wg-client.conf = server public IP:port  (4) keys from same server setup"
}

func parseWireGuardConf(path string) (*WgConf, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	conf := &WgConf{
		Iface: WgConfSection{Kv: map[string]string{}},
		Peer:  WgConfSection{Kv: map[string]string{}},
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
			conf.Iface.Kv[strings.ToLower(key)] = val
		case "peer":
			conf.Peer.Kv[strings.ToLower(key)] = val
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if conf.Iface.Kv["privatekey"] == "" {
		return nil, fmt.Errorf("missing [Interface] PrivateKey")
	}
	if conf.Peer.Kv["publickey"] == "" {
		return nil, fmt.Errorf("missing [Peer] PublicKey")
	}
	return conf, nil
}

func applyWireGuardConf(dev string, conf *WgConf, mtu int) error {
	platform.NlDown(dev)

	if err := platform.Run("ip", "link", "add", dev, "type", "wireguard"); err != nil {
		return fmt.Errorf("ip link add: %w (platform.Try: modprobe wireguard)", err)
	}

	privKey := conf.Iface.Kv["privatekey"]
	if err := wgSetKey(dev, "private-key", privKey, "wg"); err != nil {
		platform.NlDown(dev)
		return err
	}

	if lp := conf.Iface.Kv["listenport"]; lp != "" {
		if err := platform.Run("wg", "set", dev, "listen-port", lp); err != nil {
			platform.NlDown(dev)
			return fmt.Errorf("wg listen-port: %w", err)
		}
		platform.LogOK("listen-port " + lp + " UDP")
	}

	pubKey := conf.Peer.Kv["publickey"]
	args := []string{"set", dev, "peer", pubKey}
	if ips := conf.Peer.Kv["allowedips"]; ips != "" {
		args = append(args, "allowed-ips", ips)
	}
	if ep := conf.Peer.Kv["endpoint"]; ep != "" {
		args = append(args, "endpoint", ep)
		platform.LogOK("peer endpoint " + ep)
	}
	if ka := conf.Peer.Kv["persistentkeepalive"]; ka != "" {
		args = append(args, "persistent-keepalive", ka)
	}
	if err := platform.Run("wg", args...); err != nil {
		platform.NlDown(dev)
		return fmt.Errorf("wg peer: %w", err)
	}

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

func wgSetKey(dev, keyType, value, wgCmd string) error {
	cmd := exec.Command(wgCmd, "set", dev, keyType, "/dev/stdin")
	cmd.Stdin = strings.NewReader(value + "\n")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("%s %s: %s", wgCmd, keyType, msg)
		}
		return fmt.Errorf("%s %s: %w", wgCmd, keyType, err)
	}
	return nil
}
