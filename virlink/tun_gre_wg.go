package main

import (
	"fmt"
	"os"

	"github.com/vishvananda/netlink"
)

const (
	greWgWgSubnet  = "10.20.6.0/30"  // WireGuard overlay
	greWgGRESubnet = "10.20.11.0/30" // GRE overlay (on top of WG)
)

// GreWgTunnel: GRE inside WireGuard — encrypted routing.
// WireGuard link creation: native (netlink.Wireguard)
// WireGuard key/peer config: `wg set` subprocess (requires wgctrl or wg binary)
// GRE interface: native (netlink.Gretun, endpoints = WG overlay IPs)
type GreWgTunnel struct{ cfg *Config }

func (t *GreWgTunnel) wgDev() string       { return "wg-gre0" }
func (t *GreWgTunnel) greDev() string      { return "gre-wg0" }
func (t *GreWgTunnel) DevName() string     { return t.greDev() }
func (t *GreWgTunnel) OverlayIP() string   { return overlayAddr(t.cfg, greWgGRESubnet) }
func (t *GreWgTunnel) PeerIP() string      { return peerAddr(t.cfg, greWgGRESubnet) }

func (t *GreWgTunnel) Up() error {
	c := t.cfg
	wg := c.GreWg
	wgDev, greDev := t.wgDev(), t.greDev()
	port := fmt.Sprint(wg.WgPort)

	var privKey, peerPubKey string
	if c.Mode == "client" {
		privKey, peerPubKey = wg.ClientPrivKey, wg.ServerPubKey
	} else {
		privKey, peerPubKey = wg.ServerPrivKey, wg.ClientPubKey
	}
	if privKey == "" || peerPubKey == "" {
		return fmt.Errorf("WireGuard keys not set — run: ./virlink keygen")
	}

	wgAddr := computeOverlay(c.Mode, greWgWgSubnet)
	wgPeer := peerAddr(c, greWgWgSubnet)
	greAddr := overlayAddr(c, greWgGRESubnet)
	grePeer := peerAddr(c, greWgGRESubnet)

	header("gre-wg / " + c.Mode)

	step("kernel modules...")
	loadModules("wireguard", "ip_gre")

	step("cleanup...")
	t.doClean()

	// ── WireGuard interface via netlink ────────────────────────────────────────
	step("WireGuard interface (netlink)...")
	wgLink := &netlink.Wireguard{
		LinkAttrs: netlink.LinkAttrs{
			Name: wgDev,
			MTU:  wg.MTU,
		},
	}
	if err := nlCreate(wgLink, wgAddr); err != nil {
		return fmt.Errorf("wg create: %w", err)
	}

	// WireGuard key + peer configuration.
	// wgctrl would be fully native; we use `wg set` for simplicity.
	step("WireGuard key + peer (wg set)...")
	if err := wgConfigure(wgDev, privKey, peerPubKey,
		port, c.RemoteIP+":"+port,
		greWgWgSubnet+","+greWgGRESubnet); err != nil {
		return err
	}
	logOK(fmt.Sprintf("WireGuard %s  %s → peer %s", wgDev, wgAddr, wgPeer))

	// ── GRE tunnel over WireGuard overlay via netlink ─────────────────────────
	// GRE endpoints are the WireGuard overlay IPs, NOT the public IPs.
	// This ensures GRE traffic goes through the encrypted WireGuard tunnel.
	step("GRE interface over WireGuard (netlink)...")
	gre := &netlink.Gretun{
		LinkAttrs: netlink.LinkAttrs{
			Name: greDev,
			MTU:  wg.MTU - 80,
		},
		Local:  mustIP4(plainIP(wgAddr)),
		Remote: mustIP4(wgPeer),
		Ttl:    255,
	}
	if err := nlCreate(gre, greAddr); err != nil {
		return fmt.Errorf("gre: %w", err)
	}
	logOK(fmt.Sprintf("GRE %s  %s  (endpoints: WG overlay)", greDev, greAddr))

	step(fmt.Sprintf("tuning (%s)...", tuningModeLabel(c)))
	applyTunnelTuning(c, wgDev, greDev)

	step("iptables MSS clamping...")
	addMSS(greDev)

	done(greDev, greAddr, grePeer,
		fmt.Sprintf("WireGuard : %s  %s  port=%s", wgDev, wgAddr, port),
		"test      : ping -c3 "+grePeer,
		"wg status : wg show "+wgDev,
	)
	return nil
}

func (t *GreWgTunnel) Down() error {
	delMSS(t.greDev())
	t.doClean()
	logOK("gre-wg torn down")
	return nil
}

func (t *GreWgTunnel) doClean() {
	restoreTunnelTuning()
	nlDown(t.greDev(), t.wgDev())
}

func (t *GreWgTunnel) Status() {
	out, _ := runOut("wg", "show", t.wgDev())
	fmt.Println(out)
	if l, err := netlink.LinkByName(t.greDev()); err == nil {
		fmt.Printf("  %s: %s\n", l.Attrs().Name, l.Type())
	}
}

// wgConfigure writes the private key and configures the peer via `wg set`.
func wgConfigure(dev, privKey, peerPubKey, listenPort, endpoint, allowedIPs string) error {
	// write private key to a temp file (avoids it appearing in process list)
	f, err := os.CreateTemp("", "wg-key-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_ = os.Chmod(f.Name(), 0600)
	if _, err := fmt.Fprintln(f, privKey); err != nil {
		f.Close()
		return err
	}
	f.Close()

	if err := run("wg", "set", dev,
		"listen-port", listenPort,
		"private-key", f.Name()); err != nil {
		return fmt.Errorf("wg set key: %w", err)
	}
	return run("wg", "set", dev,
		"peer", peerPubKey,
		"allowed-ips", allowedIPs,
		"endpoint", endpoint,
		"persistent-keepalive", "25")
}
