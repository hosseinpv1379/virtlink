// tun_wireguard.go — WireGuard site-to-site via wireguard-tools (wg + ip).
//
// virlink reads a standard wg-quick-style conf, creates the kernel interface,
// applies keys/peers, assigns the overlay address, and verifies handshake.
package virlink

import (
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

type wgConfSection struct {
	kv map[string]string
}

type wgConf struct {
	iface wgConfSection
	peer  wgConfSection
}

type WireGuardTunnel struct {
	cfg         *Config
	lockFd      *os.File
	overlayCIDR string // from wg conf Address (source of truth)
	peerPlain   string // peer overlay IP derived from AllowedIPs / config
}

func (t *WireGuardTunnel) DevName() string {
	if t.cfg.WireGuard.Dev != "" {
		return t.cfg.WireGuard.Dev
	}
	return tunnelDevName(t.cfg, "wg-virlink0")
}

func (t *WireGuardTunnel) OverlayIP() string {
	if t.overlayCIDR != "" {
		return t.overlayCIDR
	}
	return overlayAddr(t.cfg, wireguardSubnet)
}

func (t *WireGuardTunnel) PeerIP() string {
	if t.peerPlain != "" {
		return t.peerPlain
	}
	return peerAddr(t.cfg, wireguardSubnet)
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

	header("wireguard / " + c.Mode)
	applyPerfFromConfig(c)
	step("cleanup...")
	t.doClean()

	var err error
	t.lockFd, err = acquireTunnelLock(dev)
	if err != nil {
		return err
	}

	step("loading wireguard kernel module...")
	_ = run("modprobe", "wireguard")

	conf, err := parseWireGuardConf(wg.Config)
	if err != nil {
		return fmt.Errorf("[wireguard] parse %q: %w", wg.Config, err)
	}
	t.overlayCIDR = firstWireGuardAddress(conf)
	t.peerPlain = wireguardPeerIP(conf, c)

	if ep := conf.peer.kv["endpoint"]; ep != "" && c.Mode == "client" {
		host, epPort, splitErr := net.SplitHostPort(ep)
		if splitErr == nil {
			if host != c.RemoteIP && net.ParseIP(host) != nil {
				logWarn(fmt.Sprintf("Endpoint %s ≠ remote_ip %s in toml — using Endpoint from wg conf", host, c.RemoteIP))
			}
			if p, _ := strconv.Atoi(epPort); p > 0 && p != port {
				logWarn(fmt.Sprintf("Endpoint port %d ≠ transport.port %d in toml — wg conf port wins", p, port))
			}
		}
	}

	step("creating WireGuard interface " + dev + "...")
	if err := applyWireGuardConf(dev, conf, c.Tunnel.MTU); err != nil {
		t.doClean()
		return err
	}

	if c.Mode == "client" {
		t.applyWireGuardClientRpFilter()
	}

	step(fmt.Sprintf("tuning (%s)...", tuningModeLabel(c)))
	applyTunnelTuning(c, dev)
	addMSS(c, dev)

	logWireGuardStatus(dev, c.Mode, "wg")

	step("waiting for WireGuard handshake...")
	if c.Mode == "client" {
		if err := waitForWireGuardHandshake(dev, "wg", 45*time.Second); err != nil {
			t.doClean()
			return err
		}
	} else if _, ok := wireguardLatestHandshake(dev, "wg"); !ok {
		logInfo("server listening — handshake will complete when the client starts")
		logInfo("ensure UDP listen-port is open in firewall (Hetzner + iptables/ufw)")
	} else {
		logOK("handshake already active")
	}

	addr := t.OverlayIP()
	peer := t.PeerIP()
	if _, ok := wireguardLatestHandshake(dev, "wg"); ok {
		logOK(fmt.Sprintf("wireguard up  dev=%s  wg-handshake=ok", dev))
	} else {
		logOK(fmt.Sprintf("wireguard up  dev=%s  wg-handshake=pending (start client)", dev))
	}
	logOK(fmt.Sprintf("overlay %s  peer %s", addr, peer))

	done(dev, addr, peer,
		fmt.Sprintf("transport : WireGuard UDP (see wg conf ListenPort / Endpoint)"),
		"config    : "+wg.Config,
		"status    : wg show "+dev,
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
	t.restoreWireGuardClientRpFilter()
	if t.lockFd != nil {
		releaseTunnelLock(t.lockFd)
		t.lockFd = nil
	}
	restoreTunnelTuning()
	delMSS(t.DevName())
	nlDown(t.DevName())
}

func (t *WireGuardTunnel) applyWireGuardClientRpFilter() {
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

func firstWireGuardAddress(conf *wgConf) string {
	raw := conf.iface.kv["address"]
	if raw == "" {
		return ""
	}
	return strings.TrimSpace(strings.Split(raw, ",")[0])
}

func wireguardPeerIP(conf *wgConf, c *Config) string {
	return wireguardPeerIPSubnet(conf, c, wireguardSubnet)
}

func wireguardPeerIPSubnet(conf *wgConf, c *Config, fallback string) string {
	if ips := conf.peer.kv["allowedips"]; ips != "" {
		part := strings.TrimSpace(strings.Split(ips, ",")[0])
		if ip, _, err := net.ParseCIDR(part); err == nil && ip != nil {
			return ip.String()
		}
	}
	return peerAddr(c, fallback)
}

func logWireGuardStatus(dev, mode, wgCmd string) {
	out, err := runOut(wgCmd, "show", dev)
	if err != nil {
		logWarn(wgCmd + " show: " + err.Error())
		return
	}
	logInfo("── " + wgCmd + " show " + dev + " ──")
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		logInfo("  " + line)
	}
	if ts, ok := wireguardLatestHandshake(dev, wgCmd); ok {
		logOK(fmt.Sprintf("latest handshake: %s ago", time.Since(ts).Round(time.Second)))
	} else if mode == "server" {
		logInfo("  no handshake yet — start the client, ensure UDP port is open on this host")
	} else {
		logWarn("  no handshake yet — check server running, UDP port/firewall, keys, Endpoint")
	}
}

func wireguardLatestHandshake(dev, wgCmd string) (time.Time, bool) {
	out, err := runOut(wgCmd, "show", dev, "latest-handshakes")
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
		if _, ok := wireguardLatestHandshake(dev, wgCmd); ok {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	hint := wireguardHandshakeHint("client")
	out, _ := runOut(wgCmd, "show", dev)
	return fmt.Errorf("WireGuard handshake timeout (%s)\n%s\n%s", timeout.Round(time.Second), hint, out)
}

func wireguardHandshakeHint(mode string) string {
	if mode == "server" {
		return "Server is listening — start the CLIENT tunnel. Open UDP listen-port in host + cloud firewall. Verify client has wg-client.conf from THIS server (matching keys)."
	}
	return "Check: (1) server tunnel started first  (2) UDP port open on server + cloud firewall  (3) Endpoint in wg-client.conf = server public IP:port  (4) keys from same server setup"
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
		return fmt.Errorf("ip link add: %w (try: modprobe wireguard)", err)
	}

	privKey := conf.iface.kv["privatekey"]
	if err := wgSetKey(dev, "private-key", privKey, "wg"); err != nil {
		nlDown(dev)
		return err
	}

	if lp := conf.iface.kv["listenport"]; lp != "" {
		if err := run("wg", "set", dev, "listen-port", lp); err != nil {
			nlDown(dev)
			return fmt.Errorf("wg listen-port: %w", err)
		}
		logOK("listen-port " + lp + " UDP")
	}

	pubKey := conf.peer.kv["publickey"]
	args := []string{"set", dev, "peer", pubKey}
	if ips := conf.peer.kv["allowedips"]; ips != "" {
		args = append(args, "allowed-ips", ips)
	}
	if ep := conf.peer.kv["endpoint"]; ep != "" {
		args = append(args, "endpoint", ep)
		logOK("peer endpoint " + ep)
	}
	if ka := conf.peer.kv["persistentkeepalive"]; ka != "" {
		args = append(args, "persistent-keepalive", ka)
	}
	if err := run("wg", args...); err != nil {
		nlDown(dev)
		return fmt.Errorf("wg peer: %w", err)
	}

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
