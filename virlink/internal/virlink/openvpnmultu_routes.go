// openvpnmultu_routes.go — overlay /32 routes with src=lo IP (netlink, no openvpn scripts).
package virlink

import (
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func openvpnMultuWorkerDevs(workers []openvpnMultuWorker) []string {
	devs := make([]string, len(workers))
	for i := range workers {
		devs[i] = workers[i].dev
	}
	return devs
}

func openvpnMultuActiveWorkers(workers []openvpnMultuWorker) []string {
	var active []string
	for i := range workers {
		w := &workers[i]
		if !linkUp(w.dev) {
			continue
		}
		if !openvpnLogContains(w.logPath, "Initialization Sequence Completed") {
			continue
		}
		active = append(active, w.dev)
	}
	return active
}

func openvpnMultuSyncPeerRoutes(workers []openvpnMultuWorker, localPlain, peer string) error {
	active := openvpnMultuActiveWorkers(workers)
	if len(active) == 0 {
		nlRouteDelAll(peer)
		return fmt.Errorf("no connected workers for overlay route to %s", peer)
	}
	if err := nlRouteECMPWithSrc(peer, localPlain, active...); err != nil {
		return err
	}
	return nil
}

func openvpnMultuOverlayRouteReady(peer, localPlain string, workers []openvpnMultuWorker) bool {
	peerIP := net.ParseIP(peer)
	localIP := net.ParseIP(localPlain)
	if peerIP == nil || localIP == nil {
		return false
	}
	peerIP = peerIP.To4()
	localIP = localIP.To4()
	if peerIP == nil || localIP == nil {
		return false
	}

	allowed := make(map[string]struct{}, len(workers))
	for _, w := range workers {
		allowed[w.dev] = struct{}{}
	}

	routes, err := netlink.RouteList(nil, unix.AF_INET)
	if err != nil {
		return false
	}
	for _, r := range routes {
		if !routeMatchesHost32(r, peerIP) {
			continue
		}
		if r.Src == nil || !r.Src.Equal(localIP) {
			continue
		}
		if r.LinkIndex > 0 {
			if l, e := netlink.LinkByIndex(r.LinkIndex); e == nil {
				if _, ok := allowed[l.Attrs().Name]; ok {
					return true
				}
			}
		}
		for _, nh := range r.MultiPath {
			if l, e := netlink.LinkByIndex(nh.LinkIndex); e == nil {
				if _, ok := allowed[l.Attrs().Name]; ok {
					return true
				}
			}
		}
	}
	return false
}

func openvpnMultuWaitOverlayRoute(workers []openvpnMultuWorker, localPlain, peer string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := openvpnMultuSyncPeerRoutes(workers, localPlain, peer); err != nil {
			logDebug("openvpnmultu route sync: " + err.Error())
		} else if openvpnMultuOverlayRouteReady(peer, localPlain, workers) {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("no overlay route to %s/32 via workers with src %s after %s — check openvpn worker logs and remove stale routes (ip route show %s)",
		peer, localPlain, timeout.Round(time.Second), peer)
}

func (t *OpenvpnMultuTunnel) maintainOverlayRoutes() {
	peer := t.PeerIP()
	local := plainIP(t.OverlayIP())
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		if err := openvpnMultuSyncPeerRoutes(t.workers, local, peer); err != nil {
			logDebug("openvpnmultu route sync: " + err.Error())
		}
		select {
		case <-t.routeStop:
			return
		case <-ticker.C:
		}
	}
}
