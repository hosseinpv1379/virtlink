package kernel

import (
	"virlink/internal/wire"
	"virlink/internal/platform"
	"virlink/internal/core"
	"virlink/internal/config"
	"fmt"

	"github.com/vishvananda/netlink"
)

const greFouSubnet = "10.20.1.0/30"

// GreFouTunnel: GRE encapsulated in UDP (Foo-over-UDP).
// Kernel path:
//   ip_gre + fou modules
//   FOU listener → GENL socket  (still via `ip fou` subprocess)
//   GRE interface → netlink.Gretun (native)
type GreFouTunnel struct{ cfg *config.Config }

func (t *GreFouTunnel) DevName() string    { return platform.TunnelDevName(t.cfg, "gre-fou0") }
func (t *GreFouTunnel) dev() string        { return t.DevName() }
func (t *GreFouTunnel) OverlayIP() string  { return core.OverlayAddr(t.cfg, greFouSubnet) }
func (t *GreFouTunnel) PeerIP() string     { return core.PeerAddr(t.cfg, greFouSubnet) }

func (t *GreFouTunnel) Up() error {
	c := t.cfg
	port := c.GreFou.Port
	dev := t.dev()
	addr := core.OverlayAddr(c, greFouSubnet)
	peer := core.PeerAddr(c, greFouSubnet)

	platform.Header("gre-fou / " + c.Mode)

	platform.Step("kernel modules...")
	platform.LoadModules("ip_gre", "fou")

	platform.Step("cleanup...")
	t.doClean()

	// FOU listener creation requires the "fou" GENL family.
	// We use `ip fou` here; all subsequent network operations are native.
	platform.Step(fmt.Sprintf("FOU listener UDP:%d (GENL)...", port))
	if err := platform.Run("ip", "fou", "add", "port", fmt.Sprint(port), "ipproto", "47"); err != nil {
		return fmt.Errorf("fou listener: %w", err)
	}

	// ── Create GRE interface via netlink.Gretun ───────────────────────────────
	platform.Step("GRE interface (netlink)...")
	gre := &netlink.Gretun{
		LinkAttrs: netlink.LinkAttrs{
			Name: dev,
			MTU:  c.GreFou.MTU,
		},
		Local:      platform.MustIP4(c.LocalIP),
		Remote:     platform.MustIP4(c.RemoteIP),
		Ttl:        255,
		EncapType:  platform.TunnelEncapFOU,
		EncapSport: uint16(port),
		EncapDport: uint16(port),
	}
	if err := platform.NlCreate(gre, addr); err != nil {
		return err
	}
	platform.LogOK(fmt.Sprintf("%s  %s  MTU=%d", dev, addr, c.GreFou.MTU))

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

func (t *GreFouTunnel) Down() error {
	wire.KernelTunnelWireDown(t.cfg)
	platform.DelMSS(t.dev())
	t.doClean()
	platform.LogOK("gre-fou torn down")
	return nil
}

func (t *GreFouTunnel) doClean() {
	platform.RestoreTunnelTuning()
	platform.NlDown(t.dev())
	platform.Try("ip", "fou", "del", "port", fmt.Sprint(t.cfg.GreFou.Port))
}

func (t *GreFouTunnel) Status() {
	if l, err := netlink.LinkByName(t.dev()); err == nil {
		fmt.Printf("  %s: %s  flags=%v\n",
			l.Attrs().Name, l.Type(), l.Attrs().Flags)
	} else {
		fmt.Println("  interface not found:", t.dev())
	}
	addrs, _ := netlink.AddrList(nil, 2 /* FAMILY_V4 */)
	for _, a := range addrs {
		if l, _ := netlink.LinkByIndex(a.LinkIndex); l != nil &&
			l.Attrs().Name == t.dev() {
			fmt.Println("  addr:", a.IPNet)
		}
	}
}
