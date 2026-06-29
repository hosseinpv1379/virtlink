package kernel

import (
	"virlink/internal/wire"
	"virlink/internal/platform"
	"virlink/internal/core"
	"virlink/internal/config"
	"fmt"

	"github.com/vishvananda/netlink"
)

const l2tpSubnet = "10.20.5.0/30"

// L2tpv3Tunnel: L2TPv3 over UDP — kernel-native L2 tunnel.
// L2TP tunnel/session creation requires the "l2tp" Generic Netlink family
// which is not yet in vishvananda/netlink, so we use `ip l2tp` subprocess.
// IP address + MSS rules: native netlink.
type L2tpv3Tunnel struct{ cfg *config.Config }

func (t *L2tpv3Tunnel) DevName() string    { return platform.TunnelDevName(t.cfg, "l2tp-tun0") }
func (t *L2tpv3Tunnel) dev() string        { return t.DevName() }
func (t *L2tpv3Tunnel) OverlayIP() string  { return core.OverlayAddr(t.cfg, l2tpSubnet) }
func (t *L2tpv3Tunnel) PeerIP() string     { return core.PeerAddr(t.cfg, l2tpSubnet) }

func (t *L2tpv3Tunnel) Up() error {
	c := t.cfg
	l := c.L2tpv3
	dev := t.dev()
	port := fmt.Sprint(l.Port)
	addr := core.OverlayAddr(c, l2tpSubnet)
	peer := core.PeerAddr(c, l2tpSubnet)

	var localTID, peerTID, localSID, peerSID int
	if c.Mode == "client" {
		localTID, peerTID = l.ClientTunnelID, l.ServerTunnelID
		localSID, peerSID = l.ClientSessionID, l.ServerSessionID
	} else {
		localTID, peerTID = l.ServerTunnelID, l.ClientTunnelID
		localSID, peerSID = l.ServerSessionID, l.ClientSessionID
	}

	platform.Header("l2tpv3 / " + c.Mode)

	platform.Step("kernel modules...")
	platform.LoadModules("l2tp_core", "l2tp_netlink", "l2tp_eth")

	// Check l2tp_eth is loaded (it needs linux-modules-extra on some distros)
	if out, _ := platform.RunOut("lsmod"); !platform.Contains(out, "l2tp_eth") {
		return fmt.Errorf("l2tp_eth not loaded — install: apt install linux-modules-extra-$(uname -r)")
	}
	platform.LogOK("l2tp modules verified")

	platform.Step("cleanup...")
	t.doClean(localTID, localSID)

	// L2TP tunnel + session via GENL (`ip l2tp` subprocess)
	platform.Step("L2TP tunnel (l2tp GENL)...")
	if err := platform.Run("ip", "l2tp", "add", "tunnel",
		"remote", c.RemoteIP, "local", c.LocalIP,
		"tunnel_id", fmt.Sprint(localTID),
		"peer_tunnel_id", fmt.Sprint(peerTID),
		"encap", "udp",
		"udp_sport", port, "udp_dport", port); err != nil {
		return fmt.Errorf("l2tp tunnel: %w", err)
	}

	platform.Step("L2TP session (l2tp GENL)...")
	if err := platform.Run("ip", "l2tp", "add", "session",
		"name", dev,
		"tunnel_id", fmt.Sprint(localTID),
		"session_id", fmt.Sprint(localSID),
		"peer_session_id", fmt.Sprint(peerSID)); err != nil {
		return fmt.Errorf("l2tp session: %w", err)
	}

	// ── IP address + bring up: native netlink ─────────────────────────────────
	platform.Step("IP address + up (netlink)...")
	l2tpLink, err := netlink.LinkByName(dev)
	if err != nil {
		return fmt.Errorf("l2tp link %s: %w", dev, err)
	}
	if err := netlink.LinkSetMTU(l2tpLink, l.MTU); err != nil {
		return fmt.Errorf("set mtu: %w", err)
	}
	ipAddr, err := netlink.ParseAddr(addr)
	if err != nil {
		return err
	}
	if err := netlink.AddrAdd(l2tpLink, ipAddr); err != nil {
		return fmt.Errorf("addr add: %w", err)
	}
	if err := netlink.LinkSetUp(l2tpLink); err != nil {
		return fmt.Errorf("link up: %w", err)
	}
	platform.LogOK(fmt.Sprintf("%s  %s  MTU=%d", dev, addr, l.MTU))

	platform.Step(fmt.Sprintf("tuning (%s)...", platform.TuningModeLabel(c)))
	platform.ApplyTunnelTuning(c, dev)

	platform.Step("iptables MSS clamping...")
	platform.AddMSS(c, dev)

	if err := wire.KernelTunnelWireUp(c); err != nil {
		return err
	}

	platform.Done(dev, addr, peer,
		fmt.Sprintf("port        : %s", port),
		fmt.Sprintf("tunnel_id   : local=%d  peer=%d", localTID, peerTID),
		"test        : ping -c3 "+peer,
	)
	return nil
}

func (t *L2tpv3Tunnel) Down() error {
	wire.KernelTunnelWireDown(t.cfg)
	c := t.cfg
	l := c.L2tpv3
	var localTID, localSID int
	if c.Mode == "client" {
		localTID, localSID = l.ClientTunnelID, l.ClientSessionID
	} else {
		localTID, localSID = l.ServerTunnelID, l.ServerSessionID
	}
	platform.DelMSS(t.dev())
	t.doClean(localTID, localSID)
	platform.LogOK("l2tpv3 torn down")
	return nil
}

func (t *L2tpv3Tunnel) doClean(tid, sid int) {
	platform.RestoreTunnelTuning()
	// l2tp session/tunnel deletion must go through GENL
	platform.Try("ip", "l2tp", "del", "session",
		"tunnel_id", fmt.Sprint(tid), "session_id", fmt.Sprint(sid))
	platform.Try("ip", "l2tp", "del", "tunnel", "tunnel_id", fmt.Sprint(tid))
	// interface deletion can be native
	platform.NlDown(t.dev())
}

func (t *L2tpv3Tunnel) Status() {
	out, _ := platform.RunOut("ip", "l2tp", "show", "tunnel")
	fmt.Println(out)
	if l, err := netlink.LinkByName(t.dev()); err == nil {
		fmt.Printf("  %s: flags=%v\n", l.Attrs().Name, l.Attrs().Flags)
	}
}
