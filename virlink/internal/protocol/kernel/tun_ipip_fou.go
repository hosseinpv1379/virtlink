package kernel

import (
	"virlink/internal/wire"
	"virlink/internal/platform"
	"virlink/internal/core"
	"virlink/internal/config"
	"fmt"

	"github.com/vishvananda/netlink"
)

const ipipFouSubnet = "10.20.2.0/30"

// IpipFouTunnel: IP-in-IP encapsulated in UDP (FOU).
// Lowest overhead tunnel type — IPv4 only, no encryption.
type IpipFouTunnel struct{ cfg *config.Config }

func (t *IpipFouTunnel) DevName() string   { return platform.TunnelDevName(t.cfg, "ipip-fou0") }
func (t *IpipFouTunnel) dev() string       { return t.DevName() }
func (t *IpipFouTunnel) OverlayIP() string { return core.OverlayAddr(t.cfg, ipipFouSubnet) }
func (t *IpipFouTunnel) PeerIP() string    { return core.PeerAddr(t.cfg, ipipFouSubnet) }

func (t *IpipFouTunnel) Up() error {
	c := t.cfg
	port := c.IpipFou.Port
	dev := t.dev()
	addr := core.OverlayAddr(c, ipipFouSubnet)
	peer := core.PeerAddr(c, ipipFouSubnet)

	platform.Header("ipip-fou / " + c.Mode)

	platform.Step("kernel modules...")
	platform.LoadModules("ipip", "fou")

	platform.Step("cleanup...")
	t.doClean()

	// FOU listener — ipproto 4 = IPIP
	platform.Step(fmt.Sprintf("FOU listener UDP:%d (GENL)...", port))
	if err := platform.Run("ip", "fou", "add", "port", fmt.Sprint(port), "ipproto", "4"); err != nil {
		return fmt.Errorf("fou listener: %w", err)
	}

	// ── Create IPIP interface via netlink.Iptun ────────────────────────────────
	platform.Step("IPIP interface (netlink)...")
	ipip := &netlink.Iptun{
		LinkAttrs: netlink.LinkAttrs{
			Name: dev,
			MTU:  c.IpipFou.MTU,
		},
		Local:      platform.MustIP4(c.LocalIP),
		Remote:     platform.MustIP4(c.RemoteIP),
		Ttl:        255,
		EncapType:  platform.TunnelEncapFOU,
		EncapSport: uint16(port),
		EncapDport: uint16(port),
	}
	if err := platform.NlCreate(ipip, addr); err != nil {
		return err
	}
	platform.LogOK(fmt.Sprintf("%s  %s  MTU=%d", dev, addr, c.IpipFou.MTU))

	platform.Step(fmt.Sprintf("tuning (%s)...", platform.TuningModeLabel(c)))
	platform.ApplyTunnelTuning(c, dev)

	platform.Step("iptables MSS clamping...")
	platform.AddMSS(c, dev)

	if err := wire.KernelTunnelWireUp(c); err != nil {
		return err
	}

	platform.Done(dev, addr, peer,
		fmt.Sprintf("FOU port : %d", port),
		"test     : ping -c3 "+peer,
	)
	return nil
}

func (t *IpipFouTunnel) Down() error {
	wire.KernelTunnelWireDown(t.cfg)
	platform.DelMSS(t.dev())
	t.doClean()
	platform.LogOK("ipip-fou torn down")
	return nil
}

func (t *IpipFouTunnel) doClean() {
	platform.RestoreTunnelTuning()
	platform.NlDown(t.dev(), "tunl0") // tunl0 is the kernel default IPIP device
	platform.Try("ip", "fou", "del", "port", fmt.Sprint(t.cfg.IpipFou.Port))
}

func (t *IpipFouTunnel) Status() {
	if l, err := netlink.LinkByName(t.dev()); err == nil {
		fmt.Printf("  %s: %s\n", l.Attrs().Name, l.Type())
	}
}
