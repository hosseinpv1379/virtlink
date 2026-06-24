package main

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

const l2tpSubnet = "10.20.5.0/30"

// L2tpv3Tunnel: L2TPv3 over UDP — kernel-native L2 tunnel.
// L2TP tunnel/session creation requires the "l2tp" Generic Netlink family
// which is not yet in vishvananda/netlink, so we use `ip l2tp` subprocess.
// IP address + MSS rules: native netlink.
type L2tpv3Tunnel struct{ cfg *Config }

func (t *L2tpv3Tunnel) DevName() string    { return "l2tp-tun0" }
func (t *L2tpv3Tunnel) dev() string        { return t.DevName() }
func (t *L2tpv3Tunnel) OverlayIP() string  { return overlayAddr(t.cfg, l2tpSubnet) }
func (t *L2tpv3Tunnel) PeerIP() string     { return peerAddr(t.cfg, l2tpSubnet) }

func (t *L2tpv3Tunnel) Up() error {
	c := t.cfg
	l := c.L2tpv3
	dev := t.dev()
	port := fmt.Sprint(l.Port)
	addr := overlayAddr(c, l2tpSubnet)
	peer := peerAddr(c, l2tpSubnet)

	var localTID, peerTID, localSID, peerSID int
	if c.Mode == "client" {
		localTID, peerTID = l.ClientTunnelID, l.ServerTunnelID
		localSID, peerSID = l.ClientSessionID, l.ServerSessionID
	} else {
		localTID, peerTID = l.ServerTunnelID, l.ClientTunnelID
		localSID, peerSID = l.ServerSessionID, l.ClientSessionID
	}

	header("l2tpv3 / " + c.Mode)

	step("kernel modules...")
	loadModules("l2tp_core", "l2tp_netlink", "l2tp_eth")

	// Check l2tp_eth is loaded (it needs linux-modules-extra on some distros)
	if out, _ := runOut("lsmod"); !contains(out, "l2tp_eth") {
		return fmt.Errorf("l2tp_eth not loaded — install: apt install linux-modules-extra-$(uname -r)")
	}
	logOK("l2tp modules verified")

	step("sysctl (via /proc/sys)...")
	applySysctl()

	step("cleanup...")
	t.doClean(localTID, localSID)

	// L2TP tunnel + session via GENL (`ip l2tp` subprocess)
	step("L2TP tunnel (l2tp GENL)...")
	if err := run("ip", "l2tp", "add", "tunnel",
		"remote", c.RemoteIP, "local", c.LocalIP,
		"tunnel_id", fmt.Sprint(localTID),
		"peer_tunnel_id", fmt.Sprint(peerTID),
		"encap", "udp",
		"udp_sport", port, "udp_dport", port); err != nil {
		return fmt.Errorf("l2tp tunnel: %w", err)
	}

	step("L2TP session (l2tp GENL)...")
	if err := run("ip", "l2tp", "add", "session",
		"name", dev,
		"tunnel_id", fmt.Sprint(localTID),
		"session_id", fmt.Sprint(localSID),
		"peer_session_id", fmt.Sprint(peerSID)); err != nil {
		return fmt.Errorf("l2tp session: %w", err)
	}

	// ── IP address + bring up: native netlink ─────────────────────────────────
	step("IP address + up (netlink)...")
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
	logOK(fmt.Sprintf("%s  %s  MTU=%d", dev, addr, l.MTU))

	step("iptables MSS clamping...")
	addMSS(dev)

	done(dev, addr, peer,
		fmt.Sprintf("port        : %s", port),
		fmt.Sprintf("tunnel_id   : local=%d  peer=%d", localTID, peerTID),
		"test        : ping -c3 "+peer,
	)
	return nil
}

func (t *L2tpv3Tunnel) Down() error {
	c := t.cfg
	l := c.L2tpv3
	var localTID, localSID int
	if c.Mode == "client" {
		localTID, localSID = l.ClientTunnelID, l.ClientSessionID
	} else {
		localTID, localSID = l.ServerTunnelID, l.ServerSessionID
	}
	delMSS(t.dev())
	t.doClean(localTID, localSID)
	logOK("l2tpv3 torn down")
	return nil
}

func (t *L2tpv3Tunnel) doClean(tid, sid int) {
	// l2tp session/tunnel deletion must go through GENL
	try("ip", "l2tp", "del", "session",
		"tunnel_id", fmt.Sprint(tid), "session_id", fmt.Sprint(sid))
	try("ip", "l2tp", "del", "tunnel", "tunnel_id", fmt.Sprint(tid))
	// interface deletion can be native
	nlDown(t.dev())
}

func (t *L2tpv3Tunnel) Status() {
	out, _ := runOut("ip", "l2tp", "show", "tunnel")
	fmt.Println(out)
	if l, err := netlink.LinkByName(t.dev()); err == nil {
		fmt.Printf("  %s: flags=%v\n", l.Attrs().Name, l.Attrs().Flags)
	}
}
