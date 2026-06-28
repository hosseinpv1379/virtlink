//go:build linux

package virlink

import (
	"fmt"
	"net"
	"os"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const wireLoLabel = "lo:virlink_wire"

// tcpWireKernelUp prepares client routing for FREEBIND spoof src.
func tcpWireKernelUp(cfg *Config) error {
	if cfg.Mode == "server" {
		// Remove stale lo alias from older releases that listened on wire srcip.
		wireLoAddrDel(cfg.Mangle.SrcIP)
		return nil
	}
	_ = nlSysctl("net.ipv4.conf.all.accept_local", "1")
	_ = nlSysctl("net.ipv4.conf.lo.accept_local", "1")

	if err := wireLoAddrAdd(cfg.Mangle.SrcIP); err != nil {
		return err
	}
	if err := nlRouteToPeerWithWireSrc(cfg.RemoteIP, cfg.Mangle.SrcIP); err != nil {
		wireLoAddrDel(cfg.Mangle.SrcIP)
		return err
	}
	logOK(fmt.Sprintf("wire TCP: lo %s/32 + route %s src %s",
		cfg.Mangle.SrcIP, cfg.RemoteIP, cfg.Mangle.SrcIP))
	return nil
}

func tcpWireKernelDown(cfg *Config) {
	if cfg.Mode != "client" {
		return
	}
	nlRouteDelWireSrc(cfg.RemoteIP, cfg.Mangle.SrcIP)
	wireLoAddrDel(cfg.Mangle.SrcIP)
}

func wireLoAddrAdd(ip string) error {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("wire lo: %w", err)
	}
	addr, err := netlink.ParseAddr(ip + "/32")
	if err != nil {
		return fmt.Errorf("wire addr: %w", err)
	}
	addr.Label = wireLoLabel
	if err := netlink.AddrAdd(lo, addr); err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("wire addr add %s: %w", ip, err)
		}
	}
	return nil
}

func wireLoAddrDel(ip string) {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return
	}
	addr, err := netlink.ParseAddr(ip + "/32")
	if err != nil {
		return
	}
	addr.Label = wireLoLabel
	_ = netlink.AddrDel(lo, addr)
}

// nlRouteToPeerWithWireSrc installs /32→peer using [mangle] srcip for egress lookup.
func nlRouteToPeerWithWireSrc(peer, wireSrc string) error {
	peerIP := net.ParseIP(peer)
	srcIP := net.ParseIP(wireSrc)
	if peerIP == nil || srcIP == nil {
		return fmt.Errorf("invalid peer=%q wireSrc=%q", peer, wireSrc)
	}
	peerIP = peerIP.To4()
	srcIP = srcIP.To4()
	if peerIP == nil || srcIP == nil {
		return fmt.Errorf("wire TCP route requires IPv4")
	}

	nlRouteDelWireSrc(peer, wireSrc)

	routes, err := netlink.RouteGet(peerIP)
	if err != nil {
		return err
	}
	if len(routes) == 0 {
		return fmt.Errorf("no route to peer %s", peer)
	}
	base := routes[0]
	route := &netlink.Route{
		Dst:       &net.IPNet{IP: peerIP, Mask: net.CIDRMask(32, 32)},
		Src:       srcIP,
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

func nlRouteDelWireSrc(dst, wireSrc string) {
	dstIP := net.ParseIP(dst)
	srcIP := net.ParseIP(wireSrc)
	if dstIP == nil || srcIP == nil {
		return
	}
	dstIP = dstIP.To4()
	srcIP = srcIP.To4()
	if dstIP == nil || srcIP == nil {
		return
	}
	routes, err := netlink.RouteList(nil, unix.AF_INET)
	if err != nil {
		return
	}
	for _, r := range routes {
		if !routeMatchesHost32(r, dstIP) {
			continue
		}
		if r.Src != nil && r.Src.Equal(srcIP) {
			_ = netlink.RouteDel(&r)
		}
	}
}
