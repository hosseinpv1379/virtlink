// tun_gre.go — plain GRE tunnel (IP protocol 47, no FOU wrapper).
//
// Uses the Linux kernel GRE driver via netlink — equivalent to:
//   ip tunnel add gre0 mode gre local <local> remote <remote>
//   ip addr add <overlay> dev gre0
//   ip link set gre0 up
//
// No userspace goroutines — the kernel handles all encapsulation.
package kernel

import (
	"virlink/internal/wire"
	"virlink/internal/platform"
	"virlink/internal/core"
	"virlink/internal/config"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

const greSubnet = "10.20.40.0/24"

// GreTunnel is a standard kernel GRE (protocol 47) tunnel.
// Traffic is encapsulated directly in GRE, not inside UDP.
type GreTunnel struct{ cfg *config.Config }

func (t *GreTunnel) DevName() string   { return platform.TunnelDevName(t.cfg, "gre0") }
func (t *GreTunnel) OverlayIP() string { return core.OverlayAddr(t.cfg, greSubnet) }
func (t *GreTunnel) PeerIP() string    { return core.PeerAddr(t.cfg, greSubnet) }

func (t *GreTunnel) Up() error {
	c := t.cfg
	dev := t.DevName()
	addr := t.OverlayIP()
	peer := t.PeerIP()
	mtu := c.Tunnel.MTU
	if mtu == 0 {
		mtu = 1476 // 1500 − 20 (IP) − 4 (GRE)
	}

	platform.Header("gre / " + c.Mode)

	platform.Step("kernel modules...")
	platform.LoadModules("ip_gre")

	platform.Step("cleanup...")
	platform.NlDown(dev)

	platform.Step(fmt.Sprintf("GRE interface %s (netlink)...", dev))
	link := &netlink.Gretun{
		LinkAttrs: netlink.LinkAttrs{Name: dev, MTU: mtu},
		Local:     net.ParseIP(c.LocalIP).To4(),
		Remote:    net.ParseIP(c.RemoteIP).To4(),
		Ttl:       255,
		PMtuDisc:  1,
	}
	if err := platform.NlCreate(link, addr); err != nil {
		return fmt.Errorf("gre: %w", err)
	}
	platform.LogOK(fmt.Sprintf("%s  %s  MTU=%d", dev, addr, mtu))

	platform.Step(fmt.Sprintf("tuning (%s)...", platform.TuningModeLabel(c)))
	platform.ApplyTunnelTuning(c, dev)

	platform.Step("iptables MSS clamping...")
	platform.AddMSS(c, dev)

	if err := wire.KernelTunnelWireUp(c); err != nil {
		return err
	}

	platform.Done(dev, addr, peer,
		"proto  : GRE (IP protocol 47, no UDP wrapper)",
		fmt.Sprintf("local  : %s   remote : %s", c.LocalIP, c.RemoteIP),
		"test   : ping -c3 "+peer,
	)
	return nil
}

func (t *GreTunnel) Down() error {
	wire.KernelTunnelWireDown(t.cfg)
	platform.DelMSS(t.DevName())
	platform.RestoreTunnelTuning()
	platform.NlDown(t.DevName())
	platform.LogOK("gre torn down")
	return nil
}

func (t *GreTunnel) Status() {
	if l, err := netlink.LinkByName(t.DevName()); err == nil {
		fmt.Printf("  %s: flags=%v  mtu=%d\n", l.Attrs().Name, l.Attrs().Flags, l.Attrs().MTU)
	}
}
