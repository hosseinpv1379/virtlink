// netops.go — native netlink + sysctl operations.
// This is the core of virlink: every network operation here talks directly
// to the Linux kernel via netlink sockets, no subprocess needed.
package virlink

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// FOU encap type constant (TUNNEL_ENCAP_FOU = 1)
const tunnelEncapFOU uint16 = 1

// ── link lifecycle ────────────────────────────────────────────────────────────

// nlCreate deletes any existing link with the same name, adds the new one,
// sets MTU (if Attrs.MTU > 0), assigns the CIDR address, and brings it up.
func nlCreate(link netlink.Link, cidr string) error {
	name := link.Attrs().Name

	// clean up any leftover
	if existing, err := netlink.LinkByName(name); err == nil {
		if err := netlink.LinkDel(existing); err != nil {
			return fmt.Errorf("del existing %s: %w", name, err)
		}
	}

	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("link add %s: %w", name, err)
	}

	// re-fetch to get kernel-assigned index
	l, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("lookup %s after add: %w", name, err)
	}

	if link.Attrs().MTU > 0 {
		if err := netlink.LinkSetMTU(l, link.Attrs().MTU); err != nil {
			return fmt.Errorf("set mtu %s: %w", name, err)
		}
	}

	if cidr != "" {
		addr, err := netlink.ParseAddr(cidr)
		if err != nil {
			return fmt.Errorf("parse addr %q: %w", cidr, err)
		}
		if err := netlink.AddrAdd(l, addr); err != nil {
			return fmt.Errorf("addr add %s on %s: %w", cidr, name, err)
		}
	}

	if err := netlink.LinkSetUp(l); err != nil {
		return fmt.Errorf("link up %s: %w", name, err)
	}
	return nil
}

// nlUp brings up an existing interface by name (no address change).
func nlUp(name string) error {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("link %s not found: %w", name, err)
	}
	return netlink.LinkSetUp(l)
}

// nlDown silently deletes interfaces — best-effort cleanup.
func nlDown(names ...string) {
	for _, name := range names {
		if l, err := netlink.LinkByName(name); err == nil {
			_ = netlink.LinkDel(l)
		}
	}
}

// nlSetMaster attaches a slave interface to a master (bond/bridge).
func nlSetMaster(slaveName, masterName string) error {
	slave, err := netlink.LinkByName(slaveName)
	if err != nil {
		return fmt.Errorf("slave %s: %w", slaveName, err)
	}
	master, err := netlink.LinkByName(masterName)
	if err != nil {
		return fmt.Errorf("master %s: %w", masterName, err)
	}
	return netlink.LinkSetMaster(slave, master)
}

// ── routing ───────────────────────────────────────────────────────────────────

// nlRouteAdd adds a simple host route (/32) via a device.
func nlRouteAdd(dst, dev string) error {
	dstIP := net.ParseIP(dst)
	if dstIP == nil {
		return fmt.Errorf("invalid dst IP: %s", dst)
	}
	l, err := netlink.LinkByName(dev)
	if err != nil {
		return fmt.Errorf("link %s: %w", dev, err)
	}
	return netlink.RouteReplace(&netlink.Route{
		LinkIndex: l.Attrs().Index,
		Dst:       &net.IPNet{IP: dstIP.To4(), Mask: net.CIDRMask(32, 32)},
	})
}

// nlRouteECMP installs an ECMP /32 host route via multiple devices.
// Traffic is distributed per-flow across all nexthops.
func nlRouteECMP(dst string, devs ...string) error {
	dstIP := net.ParseIP(dst)
	if dstIP == nil {
		return fmt.Errorf("invalid dst: %s", dst)
	}
	dstNet := &net.IPNet{IP: dstIP.To4(), Mask: net.CIDRMask(32, 32)}

	nlRouteDelAll(dst)

	route := &netlink.Route{Dst: dstNet}
	for _, name := range devs {
		l, err := netlink.LinkByName(name)
		if err != nil {
			return fmt.Errorf("ecmp nexthop %s: %w", name, err)
		}
		route.MultiPath = append(route.MultiPath, &netlink.NexthopInfo{
			LinkIndex: l.Attrs().Index,
			Hops:      0, // Hops=0 means weight 1
		})
	}
	return netlink.RouteReplace(route)
}

// nlRouteDelAll removes every /32 route to dst (single-path or ECMP).
func nlRouteDelAll(dst string) {
	dstIP := net.ParseIP(dst)
	if dstIP == nil {
		return
	}
	dstIP = dstIP.To4()
	routes, err := netlink.RouteList(nil, unix.AF_INET)
	if err != nil {
		_ = netlink.RouteDel(&netlink.Route{
			Dst: &net.IPNet{IP: dstIP, Mask: net.CIDRMask(32, 32)},
		})
		return
	}
	for _, r := range routes {
		if routeMatchesHost32(r, dstIP) {
			_ = netlink.RouteDel(&r)
		}
	}
}

func routeMatchesHost32(r netlink.Route, ip net.IP) bool {
	if r.Dst == nil {
		return false
	}
	ones, bits := r.Dst.Mask.Size()
	return bits == 32 && ones == 32 && r.Dst.IP.Equal(ip)
}

// nlRouteDel silently removes a host /32 route (best-effort).
func nlRouteDel(dst string) {
	nlRouteDelAll(dst)
}

// ── sysctl via /proc/sys ──────────────────────────────────────────────────────
// Writing directly to /proc/sys is equivalent to running `sysctl -w key=val`
// but without forking a subprocess.

// nlSysctl writes a kernel parameter.
// key: "net.ipv4.ip_forward"  value: "1"
func nlSysctl(key, value string) error {
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	return os.WriteFile(path, []byte(value), 0644)
}

// readSysctl reads the current value of a kernel parameter (trailing newline stripped).
func readSysctl(key string) (string, error) {
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

// mustIP4 parses and returns an IPv4 address; panics on invalid input
// (config is already validated before calling).
func mustIP4(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		panic("invalid IP: " + s)
	}
	return ip.To4()
}

// contains reports whether s contains substr.
func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
