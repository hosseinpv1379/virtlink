package virlink

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

const bondedSubnet = "10.20.4.0/30"

// BondedTunnel: two parallel GRE-FOU tunnels with ECMP multipath routing.
//
// Why ECMP instead of Linux bonding?
//   GRE tunnels are POINTOPOINT,NOARP — bonding driver requires Ethernet
//   (BROADCAST) slaves and returns "Operation not supported".
//   ECMP installs a /32 route with two equal-weight nexthops; the kernel
//   hashes per TCP/UDP flow across both paths → full 2× bandwidth.
//
// All link + route operations: native netlink.
// FOU listener: `ip fou` subprocess (requires GENL "fou" family).
type BondedTunnel struct{ cfg *Config }

func (t *BondedTunnel) dev0() string       { return tunnelDevNameWithSuffix(t.cfg, "gre-mpath0", "-0") }
func (t *BondedTunnel) dev1() string       { return tunnelDevNameWithSuffix(t.cfg, "gre-mpath1", "-1") }
func (t *BondedTunnel) DevName() string    { return t.dev0() }
func (t *BondedTunnel) OverlayIP() string  { return overlayAddr(t.cfg, bondedSubnet) }
func (t *BondedTunnel) PeerIP() string     { return peerAddr(t.cfg, bondedSubnet) }

func (t *BondedTunnel) Up() error {
	c := t.cfg
	p0, p1 := c.Bonded.Port1, c.Bonded.Port2
	mtu := c.Bonded.MTU
	dev0, dev1 := t.dev0(), t.dev1()
	addr := overlayAddr(c, bondedSubnet)
	peer := peerAddr(c, bondedSubnet)

	header("bonded-gre-fou (ECMP) / " + c.Mode)

	step("kernel modules...")
	loadModules("ip_gre", "fou")

	step("cleanup...")
	t.doClean()

	// FOU listeners
	step(fmt.Sprintf("FOU listeners UDP:%d and UDP:%d...", p0, p1))
	if err := run("ip", "fou", "add", "port", fmt.Sprint(p0), "ipproto", "47"); err != nil {
		return fmt.Errorf("fou port %d: %w", p0, err)
	}
	if err := run("ip", "fou", "add", "port", fmt.Sprint(p1), "ipproto", "47"); err != nil {
		return fmt.Errorf("fou port %d: %w", p1, err)
	}

	// ── Create two GRE interfaces via netlink (different keys!) ────────────────
	// Two GREs with same local/remote MUST have different keys; otherwise the
	// kernel returns EEXIST because it uses (local, remote, key) as the hash key.
	step("GRE path-1 (netlink, key=1)...")
	gre0 := &netlink.Gretun{
		LinkAttrs:  netlink.LinkAttrs{Name: dev0, MTU: mtu},
		Local:      mustIP4(c.LocalIP),
		Remote:     mustIP4(c.RemoteIP),
		IKey:       1,
		OKey:       1,
		Ttl:        255,
		EncapType:  tunnelEncapFOU,
		EncapSport: uint16(p0),
		EncapDport: uint16(p0),
	}
	// dev0 gets the overlay address
	if err := nlCreate(gre0, addr); err != nil {
		return fmt.Errorf("%s: %w", dev0, err)
	}

	step("GRE path-2 (netlink, key=2)...")
	gre1 := &netlink.Gretun{
		LinkAttrs:  netlink.LinkAttrs{Name: dev1, MTU: mtu},
		Local:      mustIP4(c.LocalIP),
		Remote:     mustIP4(c.RemoteIP),
		IKey:       2,
		OKey:       2,
		Ttl:        255,
		EncapType:  tunnelEncapFOU,
		EncapSport: uint16(p1),
		EncapDport: uint16(p1),
	}
	// dev1 is a secondary path — no address, just brought up
	if err := nlCreate(gre1, ""); err != nil {
		return fmt.Errorf("%s: %w", dev1, err)
	}

	// ── ECMP route: peer reachable via both tunnels ────────────────────────────
	step("ECMP route (netlink, 2 nexthops)...")
	if err := nlRouteECMP(peer, dev0, dev1); err != nil {
		return fmt.Errorf("ecmp route: %w", err)
	}
	logOK(fmt.Sprintf("route %s/32 nexthop %s nexthop %s", peer, dev0, dev1))

	step(fmt.Sprintf("tuning (%s)...", tuningModeLabel(c)))
	applyTunnelTuning(c, dev0, dev1)

	step("iptables MSS clamping...")
	addMSS(c, dev0)
	addMSS(c, dev1)

	if err := kernelTunnelWireUp(c); err != nil {
		return err
	}

	done(dev0+"+"+dev1, addr, peer,
		fmt.Sprintf("path-1 : %s  FOU:%d  GRE key=1", dev0, p0),
		fmt.Sprintf("path-2 : %s  FOU:%d  GRE key=2", dev1, p1),
		"routing : ECMP /32 per-flow hashing",
		"test    : ping -c3 "+peer,
		"bw test : iperf3 -P4 -c "+peer,
	)
	return nil
}

func (t *BondedTunnel) Down() error {
	kernelTunnelWireDown(t.cfg)
	peer := peerAddr(t.cfg, bondedSubnet)
	nlRouteDel(peer)
	delMSS(t.dev0())
	delMSS(t.dev1())
	t.doClean()
	logOK("bonded-gre-fou (ECMP) torn down")
	return nil
}

func (t *BondedTunnel) doClean() {
	restoreTunnelTuning()
	nlDown(t.dev0(), t.dev1())
	try("ip", "fou", "del", "port", fmt.Sprint(t.cfg.Bonded.Port1))
	try("ip", "fou", "del", "port", fmt.Sprint(t.cfg.Bonded.Port2))
}

func (t *BondedTunnel) Status() {
	peer := peerAddr(t.cfg, bondedSubnet)
	for _, name := range []string{t.dev0(), t.dev1()} {
		if l, err := netlink.LinkByName(name); err == nil {
			fmt.Printf("  %s: %s  flags=%v\n", name, l.Type(), l.Attrs().Flags)
		}
	}
	out, _ := runOut("ip", "route", "show", peer+"/32")
	fmt.Println("  ECMP:", out)
}
