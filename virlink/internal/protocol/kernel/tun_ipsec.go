package kernel

import (
	"virlink/internal/wire"
	"virlink/internal/platform"
	"virlink/internal/core"
	"virlink/internal/config"
	"fmt"

	"github.com/vishvananda/netlink"
)

const ipsecSubnet = "10.20.8.0/30"

// IpsecTunnel: GRE-FOU + IPsec ESP transport mode encryption.
// GRE interface: native (netlink.Gretun)
// IPsec xfrm states/policies: `ip xfrm` subprocess (XFRM netlink is complex)
type IpsecTunnel struct{ cfg *config.Config }

func (t *IpsecTunnel) DevName() string    { return platform.TunnelDevName(t.cfg, "gre-ipsec0") }
func (t *IpsecTunnel) dev() string        { return t.DevName() }
func (t *IpsecTunnel) OverlayIP() string  { return core.OverlayAddr(t.cfg, ipsecSubnet) }
func (t *IpsecTunnel) PeerIP() string     { return core.PeerAddr(t.cfg, ipsecSubnet) }

func (t *IpsecTunnel) Up() error {
	c := t.cfg
	ip := c.Ipsec
	dev := t.dev()
	port := fmt.Sprint(ip.Port)
	addr := core.OverlayAddr(c, ipsecSubnet)
	peer := core.PeerAddr(c, ipsecSubnet)

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

	platform.Header("gre-fou-ipsec / " + c.Mode)

	platform.Step("kernel modules...")
	platform.LoadModules("ip_gre", "fou", "esp4", "xfrm4_tunnel")

	platform.Step("cleanup...")
	t.doClean(port, spiOut, spiIn)

	// FOU listener
	platform.Step(fmt.Sprintf("FOU listener UDP:%s (GENL)...", port))
	if err := platform.Run("ip", "fou", "add", "port", port, "ipproto", "47"); err != nil {
		return fmt.Errorf("fou: %w", err)
	}

	// ── GRE interface via netlink ─────────────────────────────────────────────
	platform.Step("GRE interface (netlink)...")
	gre := &netlink.Gretun{
		LinkAttrs:  netlink.LinkAttrs{Name: dev, MTU: ip.MTU},
		Local:      platform.MustIP4(c.LocalIP),
		Remote:     platform.MustIP4(c.RemoteIP),
		Ttl:        255,
		EncapType:  platform.TunnelEncapFOU,
		EncapSport: uint16(ip.Port),
		EncapDport: uint16(ip.Port),
	}
	if err := platform.NlCreate(gre, addr); err != nil {
		return err
	}
	platform.LogOK(fmt.Sprintf("%s  %s", dev, addr))

	platform.Step(fmt.Sprintf("tuning (%s)...", platform.TuningModeLabel(c)))
	platform.ApplyTunnelTuning(c, dev)

	// ── IPsec xfrm (XFRM netlink — using ip xfrm for simplicity) ─────────────
	platform.Step("IPsec xfrm states (SA)...")
	if err := platform.Run("ip", "xfrm", "state", "add",
		"src", c.LocalIP, "dst", c.RemoteIP,
		"proto", "esp", "spi", spiOut, "mode", "transport",
		"enc", "cbc(aes)", encOut,
		"auth-trunc", "hmac(sha256)", authOut, "128"); err != nil {
		return fmt.Errorf("xfrm SA out: %w", err)
	}
	if err := platform.Run("ip", "xfrm", "state", "add",
		"src", c.RemoteIP, "dst", c.LocalIP,
		"proto", "esp", "spi", spiIn, "mode", "transport",
		"enc", "cbc(aes)", encIn,
		"auth-trunc", "hmac(sha256)", authIn, "128"); err != nil {
		return fmt.Errorf("xfrm SA in: %w", err)
	}

	platform.Step("IPsec xfrm policies...")
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
		if err := platform.Run(a[0], a[1:]...); err != nil {
			platform.LogWarn("xfrm policy: " + err.Error())
		}
	}

	platform.Step("iptables MSS clamping...")
	platform.AddMSS(c, dev)

	if err := wire.KernelTunnelWireUp(c); err != nil {
		return err
	}

	platform.Done(dev, addr, peer,
		fmt.Sprintf("FOU port : %s", port),
		fmt.Sprintf("IPsec SPI: out=%s  in=%s", spiOut, spiIn),
		"⚠ replace test keys with random values in production",
		"test     : ping -c3 "+peer,
	)
	return nil
}

func (t *IpsecTunnel) Down() error {
	wire.KernelTunnelWireDown(t.cfg)
	c := t.cfg
	ip := c.Ipsec
	port := fmt.Sprint(ip.Port)
	var spiOut, spiIn string
	if c.Mode == "client" {
		spiOut, spiIn = ip.SpiOut, ip.SpiIn
	} else {
		spiOut, spiIn = ip.SpiIn, ip.SpiOut
	}
	platform.DelMSS(t.dev())
	t.doClean(port, spiOut, spiIn)
	platform.LogOK("gre-fou-ipsec torn down")
	return nil
}

func (t *IpsecTunnel) doClean(port, spiOut, spiIn string) {
	platform.RestoreTunnelTuning()
	platform.NlDown(t.dev())
	platform.Try("ip", "fou", "del", "port", port)
	c := t.cfg
	platform.Try("ip", "xfrm", "policy", "del",
		"src", c.LocalIP, "dst", c.RemoteIP, "proto", "udp", "dport", port, "dir", "out")
	platform.Try("ip", "xfrm", "policy", "del",
		"src", c.RemoteIP, "dst", c.LocalIP, "proto", "udp", "dport", port, "dir", "in")
	platform.Try("ip", "xfrm", "policy", "del",
		"src", c.RemoteIP, "dst", c.LocalIP, "proto", "udp", "dport", port, "dir", "fwd")
	platform.Try("ip", "xfrm", "state", "del",
		"src", c.LocalIP, "dst", c.RemoteIP, "proto", "esp", "spi", spiOut)
	platform.Try("ip", "xfrm", "state", "del",
		"src", c.RemoteIP, "dst", c.LocalIP, "proto", "esp", "spi", spiIn)
}

func (t *IpsecTunnel) Status() {
	out, _ := platform.RunOut("ip", "xfrm", "state", "list")
	fmt.Println("── xfrm states ──\n" + out)
	if l, err := netlink.LinkByName(t.dev()); err == nil {
		fmt.Printf("  %s: %s\n", l.Attrs().Name, l.Type())
	}
}
