package main

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

const ipipFouSubnet = "10.20.2.0/30"

// IpipFouTunnel: IP-in-IP encapsulated in UDP (FOU).
// Lowest overhead tunnel type — IPv4 only, no encryption.
type IpipFouTunnel struct{ cfg *Config }

func (t *IpipFouTunnel) DevName() string   { return "ipip-fou0" }
func (t *IpipFouTunnel) dev() string       { return t.DevName() }
func (t *IpipFouTunnel) OverlayIP() string { return overlayAddr(t.cfg, ipipFouSubnet) }
func (t *IpipFouTunnel) PeerIP() string    { return peerAddr(t.cfg, ipipFouSubnet) }

func (t *IpipFouTunnel) Up() error {
	c := t.cfg
	port := c.IpipFou.Port
	dev := t.dev()
	addr := overlayAddr(c, ipipFouSubnet)
	peer := peerAddr(c, ipipFouSubnet)

	header("ipip-fou / " + c.Mode)

	step("kernel modules...")
	loadModules("ipip", "fou")

	step("cleanup...")
	t.doClean()

	// FOU listener — ipproto 4 = IPIP
	step(fmt.Sprintf("FOU listener UDP:%d (GENL)...", port))
	if err := run("ip", "fou", "add", "port", fmt.Sprint(port), "ipproto", "4"); err != nil {
		return fmt.Errorf("fou listener: %w", err)
	}

	// ── Create IPIP interface via netlink.Iptun ────────────────────────────────
	step("IPIP interface (netlink)...")
	ipip := &netlink.Iptun{
		LinkAttrs: netlink.LinkAttrs{
			Name: dev,
			MTU:  c.IpipFou.MTU,
		},
		Local:      mustIP4(c.LocalIP),
		Remote:     mustIP4(c.RemoteIP),
		Ttl:        255,
		EncapType:  tunnelEncapFOU,
		EncapSport: uint16(port),
		EncapDport: uint16(port),
	}
	if err := nlCreate(ipip, addr); err != nil {
		return err
	}
	logOK(fmt.Sprintf("%s  %s  MTU=%d", dev, addr, c.IpipFou.MTU))

	step(fmt.Sprintf("tuning (%s)...", tuningModeLabel(c)))
	applyTunnelTuning(c, dev)

	step("iptables MSS clamping...")
	addMSS(dev)

	done(dev, addr, peer,
		fmt.Sprintf("FOU port : %d", port),
		"test     : ping -c3 "+peer,
	)
	return nil
}

func (t *IpipFouTunnel) Down() error {
	delMSS(t.dev())
	t.doClean()
	logOK("ipip-fou torn down")
	return nil
}

func (t *IpipFouTunnel) doClean() {
	restoreTunnelTuning()
	nlDown(t.dev(), "tunl0") // tunl0 is the kernel default IPIP device
	try("ip", "fou", "del", "port", fmt.Sprint(t.cfg.IpipFou.Port))
}

func (t *IpipFouTunnel) Status() {
	if l, err := netlink.LinkByName(t.dev()); err == nil {
		fmt.Printf("  %s: %s\n", l.Attrs().Name, l.Type())
	}
}
