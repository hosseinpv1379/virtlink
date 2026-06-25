package virlink

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

const ipsecSubnet = "10.20.8.0/30"

// IpsecTunnel: GRE-FOU + IPsec ESP transport mode encryption.
// GRE interface: native (netlink.Gretun)
// IPsec xfrm states/policies: `ip xfrm` subprocess (XFRM netlink is complex)
type IpsecTunnel struct{ cfg *Config }

func (t *IpsecTunnel) DevName() string    { return "gre-ipsec0" }
func (t *IpsecTunnel) dev() string        { return t.DevName() }
func (t *IpsecTunnel) OverlayIP() string  { return overlayAddr(t.cfg, ipsecSubnet) }
func (t *IpsecTunnel) PeerIP() string     { return peerAddr(t.cfg, ipsecSubnet) }

func (t *IpsecTunnel) Up() error {
	c := t.cfg
	ip := c.Ipsec
	dev := t.dev()
	port := fmt.Sprint(ip.Port)
	addr := overlayAddr(c, ipsecSubnet)
	peer := peerAddr(c, ipsecSubnet)

	// SPIs are mirrored between client and server
	var spiOut, spiIn, encOut, encIn, authOut, authIn string
	if c.Mode == "client" {
		spiOut, spiIn = ip.SpiOut, ip.SpiIn
		encOut, encIn = ip.EncKeyOut, ip.EncKeyIn
		authOut, authIn = ip.AuthKeyOut, ip.AuthKeyIn
	} else {
		spiOut, spiIn = ip.SpiIn, ip.SpiOut
		encOut, encIn = ip.EncKeyIn, ip.EncKeyOut
		authOut, authIn = ip.AuthKeyIn, ip.AuthKeyOut
	}

	header("gre-fou-ipsec / " + c.Mode)

	step("kernel modules...")
	loadModules("ip_gre", "fou", "esp4", "xfrm4_tunnel")

	step("cleanup...")
	t.doClean(port, spiOut, spiIn)

	// FOU listener
	step(fmt.Sprintf("FOU listener UDP:%s (GENL)...", port))
	if err := run("ip", "fou", "add", "port", port, "ipproto", "47"); err != nil {
		return fmt.Errorf("fou: %w", err)
	}

	// ── GRE interface via netlink ─────────────────────────────────────────────
	step("GRE interface (netlink)...")
	gre := &netlink.Gretun{
		LinkAttrs:  netlink.LinkAttrs{Name: dev, MTU: ip.MTU},
		Local:      mustIP4(c.LocalIP),
		Remote:     mustIP4(c.RemoteIP),
		Ttl:        255,
		EncapType:  tunnelEncapFOU,
		EncapSport: uint16(ip.Port),
		EncapDport: uint16(ip.Port),
	}
	if err := nlCreate(gre, addr); err != nil {
		return err
	}
	logOK(fmt.Sprintf("%s  %s", dev, addr))

	step(fmt.Sprintf("tuning (%s)...", tuningModeLabel(c)))
	applyTunnelTuning(c, dev)

	// ── IPsec xfrm (XFRM netlink — using ip xfrm for simplicity) ─────────────
	step("IPsec xfrm states (SA)...")
	if err := run("ip", "xfrm", "state", "add",
		"src", c.LocalIP, "dst", c.RemoteIP,
		"proto", "esp", "spi", spiOut, "mode", "transport",
		"enc", "cbc(aes)", encOut,
		"auth-trunc", "hmac(sha256)", authOut, "128"); err != nil {
		return fmt.Errorf("xfrm SA out: %w", err)
	}
	if err := run("ip", "xfrm", "state", "add",
		"src", c.RemoteIP, "dst", c.LocalIP,
		"proto", "esp", "spi", spiIn, "mode", "transport",
		"enc", "cbc(aes)", encIn,
		"auth-trunc", "hmac(sha256)", authIn, "128"); err != nil {
		return fmt.Errorf("xfrm SA in: %w", err)
	}

	step("IPsec xfrm policies...")
	xfrmPolicies := [][]string{
		{"src", c.LocalIP, "dst", c.RemoteIP, "proto", "udp", "dport", port,
			"dir", "out", "tmpl",
			"src", c.LocalIP, "dst", c.RemoteIP, "proto", "esp", "spi", spiOut, "mode", "transport"},
		{"src", c.RemoteIP, "dst", c.LocalIP, "proto", "udp", "dport", port,
			"dir", "in", "tmpl",
			"src", c.RemoteIP, "dst", c.LocalIP, "proto", "esp", "spi", spiIn, "mode", "transport"},
		{"src", c.RemoteIP, "dst", c.LocalIP, "proto", "udp", "dport", port,
			"dir", "fwd", "tmpl",
			"src", c.RemoteIP, "dst", c.LocalIP, "proto", "esp", "spi", spiIn, "mode", "transport"},
	}
	for _, args := range xfrmPolicies {
		a := append([]string{"ip", "xfrm", "policy", "add"}, args...)
		if err := run(a[0], a[1:]...); err != nil {
			warn("xfrm policy: " + err.Error())
		}
	}

	step("iptables MSS clamping...")
	addMSS(dev)

	if err := kernelTunnelWireUp(c); err != nil {
		return err
	}

	done(dev, addr, peer,
		fmt.Sprintf("FOU port : %s", port),
		fmt.Sprintf("IPsec SPI: out=%s  in=%s", spiOut, spiIn),
		"⚠ replace test keys with random values in production",
		"test     : ping -c3 "+peer,
	)
	return nil
}

func (t *IpsecTunnel) Down() error {
	kernelTunnelWireDown(t.cfg)
	c := t.cfg
	ip := c.Ipsec
	port := fmt.Sprint(ip.Port)
	var spiOut, spiIn string
	if c.Mode == "client" {
		spiOut, spiIn = ip.SpiOut, ip.SpiIn
	} else {
		spiOut, spiIn = ip.SpiIn, ip.SpiOut
	}
	delMSS(t.dev())
	t.doClean(port, spiOut, spiIn)
	logOK("gre-fou-ipsec torn down")
	return nil
}

func (t *IpsecTunnel) doClean(port, spiOut, spiIn string) {
	restoreTunnelTuning()
	nlDown(t.dev())
	try("ip", "fou", "del", "port", port)
	c := t.cfg
	try("ip", "xfrm", "policy", "del",
		"src", c.LocalIP, "dst", c.RemoteIP, "proto", "udp", "dport", port, "dir", "out")
	try("ip", "xfrm", "policy", "del",
		"src", c.RemoteIP, "dst", c.LocalIP, "proto", "udp", "dport", port, "dir", "in")
	try("ip", "xfrm", "policy", "del",
		"src", c.RemoteIP, "dst", c.LocalIP, "proto", "udp", "dport", port, "dir", "fwd")
	try("ip", "xfrm", "state", "del",
		"src", c.LocalIP, "dst", c.RemoteIP, "proto", "esp", "spi", spiOut)
	try("ip", "xfrm", "state", "del",
		"src", c.RemoteIP, "dst", c.LocalIP, "proto", "esp", "spi", spiIn)
}

func (t *IpsecTunnel) Status() {
	out, _ := runOut("ip", "xfrm", "state", "list")
	fmt.Println("── xfrm states ──\n" + out)
	if l, err := netlink.LinkByName(t.dev()); err == nil {
		fmt.Printf("  %s: %s\n", l.Attrs().Name, l.Type())
	}
}
