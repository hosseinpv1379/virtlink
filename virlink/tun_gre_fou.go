package main

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

const greFouSubnet = "10.20.1.0/30"

// GreFouTunnel: GRE encapsulated in UDP (Foo-over-UDP).
// Kernel path:
//   ip_gre + fou modules
//   FOU listener → GENL socket  (still via `ip fou` subprocess)
//   GRE interface → netlink.Gretun (native)
type GreFouTunnel struct{ cfg *Config }

func (t *GreFouTunnel) DevName() string    { return "gre-fou0" }
func (t *GreFouTunnel) dev() string        { return t.DevName() }
func (t *GreFouTunnel) OverlayIP() string  { return overlayAddr(t.cfg, greFouSubnet) }
func (t *GreFouTunnel) PeerIP() string     { return peerAddr(t.cfg, greFouSubnet) }

func (t *GreFouTunnel) Up() error {
	c := t.cfg
	port := c.GreFou.Port
	dev := t.dev()
	addr := overlayAddr(c, greFouSubnet)
	peer := peerAddr(c, greFouSubnet)

	header("gre-fou / " + c.Mode)

	step("kernel modules...")
	loadModules("ip_gre", "fou")

	step("sysctl (via /proc/sys)...")
	applySysctl()

	step("cleanup...")
	t.doClean()

	// FOU listener creation requires the "fou" GENL family.
	// We use `ip fou` here; all subsequent network operations are native.
	step(fmt.Sprintf("FOU listener UDP:%d (GENL)...", port))
	if err := run("ip", "fou", "add", "port", fmt.Sprint(port), "ipproto", "47"); err != nil {
		return fmt.Errorf("fou listener: %w", err)
	}

	// ── Create GRE interface via netlink.Gretun ───────────────────────────────
	step("GRE interface (netlink)...")
	gre := &netlink.Gretun{
		LinkAttrs: netlink.LinkAttrs{
			Name: dev,
			MTU:  c.GreFou.MTU,
		},
		Local:      mustIP4(c.LocalIP),
		Remote:     mustIP4(c.RemoteIP),
		Ttl:        255,
		EncapType:  tunnelEncapFOU,
		EncapSport: uint16(port),
		EncapDport: uint16(port),
	}
	if err := nlCreate(gre, addr); err != nil {
		return err
	}
	logOK(fmt.Sprintf("%s  %s  MTU=%d", dev, addr, c.GreFou.MTU))

	step("iptables MSS clamping...")
	addMSS(dev)

	done(dev, addr, peer,
		fmt.Sprintf("FOU port : %d", port),
		"test     : ping -c3 "+peer,
	)
	return nil
}

func (t *GreFouTunnel) Down() error {
	delMSS(t.dev())
	t.doClean()
	logOK("gre-fou torn down")
	return nil
}

func (t *GreFouTunnel) doClean() {
	nlDown(t.dev())
	try("ip", "fou", "del", "port", fmt.Sprint(t.cfg.GreFou.Port))
}

func (t *GreFouTunnel) Status() {
	if l, err := netlink.LinkByName(t.dev()); err == nil {
		fmt.Printf("  %s: %s  flags=%v\n",
			l.Attrs().Name, l.Type(), l.Attrs().Flags)
	} else {
		fmt.Println("  interface not found:", t.dev())
	}
	addrs, _ := netlink.AddrList(nil, netlink.FAMILY_V4)
	for _, a := range addrs {
		if l, _ := netlink.LinkByIndex(a.LinkIndex); l != nil &&
			l.Attrs().Name == t.dev() {
			fmt.Println("  addr:", a.IPNet)
		}
	}
}
