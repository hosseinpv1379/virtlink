package main

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

const (
	vxlanWgWgSubnet = "10.20.7.0/30"  // WireGuard overlay
	vxlanWgOvSubnet = "10.20.12.0/30" // VXLAN overlay
)

// VxlanWgTunnel: VXLAN inside WireGuard — encrypted L2 bridging.
// WireGuard link: native (netlink.Wireguard)
// VXLAN link: native (netlink.Vxlan, remote = peer WG overlay IP)
type VxlanWgTunnel struct{ cfg *Config }

func (t *VxlanWgTunnel) wgDev() string      { return "wg-vx0" }
func (t *VxlanWgTunnel) vxlanDev() string   { return "vxlan-wg0" }
func (t *VxlanWgTunnel) DevName() string    { return t.vxlanDev() }
func (t *VxlanWgTunnel) OverlayIP() string  { return overlayAddr(t.cfg, vxlanWgOvSubnet) }
func (t *VxlanWgTunnel) PeerIP() string     { return peerAddr(t.cfg, vxlanWgOvSubnet) }

func (t *VxlanWgTunnel) Up() error {
	c := t.cfg
	wg := c.VxlanWg
	wgDev, vxDev := t.wgDev(), t.vxlanDev()
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

	wgAddr := computeOverlay(c.Mode, vxlanWgWgSubnet)
	wgPeer := peerAddr(c, vxlanWgWgSubnet)
	ovAddr := overlayAddr(c, vxlanWgOvSubnet)
	ovPeer := peerAddr(c, vxlanWgOvSubnet)

	header("vxlan-wg / " + c.Mode)

	step("kernel modules...")
	loadModules("wireguard", "vxlan")

	step("cleanup...")
	t.doClean()

	// ── WireGuard via netlink ─────────────────────────────────────────────────
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

	step("WireGuard key + peer (wg set)...")
	if err := wgConfigure(wgDev, privKey, peerPubKey,
		port, c.RemoteIP+":"+port,
		vxlanWgWgSubnet+","+vxlanWgOvSubnet); err != nil {
		return err
	}
	logOK(fmt.Sprintf("WireGuard %s  %s → peer %s", wgDev, wgAddr, wgPeer))

	// ── VXLAN over WireGuard via netlink ──────────────────────────────────────
	// Remote = peer's WireGuard overlay IP (not public IP).
	// Port 4789 = standard VXLAN UDP port.
	step(fmt.Sprintf("VXLAN VNI=%d (netlink, remote=%s)...", wg.VNI, wgPeer))
	vx := &netlink.Vxlan{
		LinkAttrs: netlink.LinkAttrs{
			Name: vxDev,
			MTU:  wg.MTU - 100,
		},
		VxlanId:  wg.VNI,
		SrcAddr:  mustIP4(plainIP(wgAddr)),
		Group:    mustIP4(wgPeer), // unicast remote = Group in vishvananda/netlink
		Port:     4789,
		Learning: true,
	}
	if err := nlCreate(vx, ovAddr); err != nil {
		return fmt.Errorf("vxlan: %w", err)
	}
	logOK(fmt.Sprintf("VXLAN %s  %s  VNI=%d", vxDev, ovAddr, wg.VNI))

	step(fmt.Sprintf("tuning (%s)...", tuningModeLabel(c)))
	applyTunnelTuning(c, wgDev, vxDev)

	step("iptables MSS clamping...")
	addMSS(vxDev)

	if err := kernelTunnelWireUp(c); err != nil {
		return err
	}

	done(vxDev, ovAddr, ovPeer,
		fmt.Sprintf("WireGuard : %s  %s  port=%s", wgDev, wgAddr, port),
		fmt.Sprintf("VXLAN VNI : %d", wg.VNI),
		"test      : ping -c3 "+ovPeer,
	)
	return nil
}

func (t *VxlanWgTunnel) Down() error {
	kernelTunnelWireDown(t.cfg)
	delMSS(t.vxlanDev())
	t.doClean()
	logOK("vxlan-wg torn down")
	return nil
}

func (t *VxlanWgTunnel) doClean() {
	restoreTunnelTuning()
	nlDown(t.vxlanDev(), t.wgDev())
}

func (t *VxlanWgTunnel) Status() {
	out, _ := runOut("wg", "show", t.wgDev())
	fmt.Println(out)
	if l, err := netlink.LinkByName(t.vxlanDev()); err == nil {
		fmt.Printf("  %s: %s\n", l.Attrs().Name, l.Type())
	}
}
