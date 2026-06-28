//go:build linux

package virlink

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const wireLoLabel = "virlink_wire"

// tcpWireKernelUp installs kernel routes/addresses so TCP wire spoof works without
// nftables IP mangling. The socket stack binds FREEBIND to [mangle] srcip and
// connects/listens on the peer wire identity ([mangle] dstip on client, srcip on server).
func tcpWireKernelUp(cfg *Config) error {
	_ = nlSysctl("net.ipv4.conf.all.accept_local", "1")
	_ = nlSysctl("net.ipv4.conf.lo.accept_local", "1")

	if cfg.Mode == "server" {
		return tcpWireServerUp(cfg)
	}
	return tcpWireClientUp(cfg)
}

func tcpWireKernelDown(cfg *Config) {
	if cfg.Mode == "server" {
		tcpWireServerDown(cfg)
	} else {
		tcpWireClientDown(cfg)
	}
}

func tcpWireServerUp(cfg *Config) error {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("wire lo: %w", err)
	}
	addr, err := netlink.ParseAddr(cfg.Mangle.SrcIP + "/32")
	if err != nil {
		return fmt.Errorf("wire addr: %w", err)
	}
	addr.Label = wireLoLabel
	if err := netlink.AddrAdd(lo, addr); err != nil {
		return fmt.Errorf("wire addr add %s: %w", cfg.Mangle.SrcIP, err)
	}
	logOK(fmt.Sprintf("wire TCP: local %s/32 on lo (listen identity)", cfg.Mangle.SrcIP))
	return nil
}

func tcpWireServerDown(cfg *Config) {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return
	}
	addr, err := netlink.ParseAddr(cfg.Mangle.SrcIP + "/32")
	if err != nil {
		return
	}
	_ = netlink.AddrDel(lo, addr)
}

func tcpWireClientUp(cfg *Config) error {
	if err := nlRouteViaPeer(cfg.Mangle.DstIP, cfg.RemoteIP); err != nil {
		return fmt.Errorf("wire route %s via %s: %w", cfg.Mangle.DstIP, cfg.RemoteIP, err)
	}
	logOK(fmt.Sprintf("wire TCP: route %s/32 via %s (dial identity)", cfg.Mangle.DstIP, cfg.RemoteIP))
	return nil
}

func tcpWireClientDown(cfg *Config) {
	nlRouteDelAll(cfg.Mangle.DstIP)
}

// nlRouteViaPeer delivers wireDst to the same nexthop used for peer (real remote_ip).
func nlRouteViaPeer(wireDst, peer string) error {
	wireIP := net.ParseIP(wireDst)
	peerIP := net.ParseIP(peer)
	if wireIP == nil || peerIP == nil {
		return fmt.Errorf("invalid wireDst=%q peer=%q", wireDst, peer)
	}
	wireIP = wireIP.To4()
	peerIP = peerIP.To4()
	if wireIP == nil || peerIP == nil {
		return fmt.Errorf("wire route requires IPv4")
	}

	nlRouteDelAll(wireDst)

	routes, err := netlink.RouteGet(peerIP)
	if err != nil {
		return err
	}
	if len(routes) == 0 {
		return fmt.Errorf("no route to peer %s", peer)
	}
	base := routes[0]
	route := &netlink.Route{
		Dst:       &net.IPNet{IP: wireIP, Mask: net.CIDRMask(32, 32)},
		LinkIndex: base.LinkIndex,
	}
	if base.Gw != nil {
		route.Gw = base.Gw
	} else {
		route.Gw = peerIP
		route.Flags = unix.RTNH_F_ONLINK
	}
	return netlink.RouteReplace(route)
}
