// openvpnmultu_routes.go — overlay /32 routes with src=lo IP (netlink, no openvpn scripts).
package virlink

import (
	"time"
)

func openvpnMultuSyncPeerRoutes(workers []openvpnMultuWorker, localPlain, peer string) {
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
	if len(active) == 0 {
		nlRouteDelAll(peer)
		return
	}
	if err := nlRouteECMPWithSrc(peer, localPlain, active...); err != nil {
		logDebug("openvpnmultu route sync: " + err.Error())
	}
}

func (t *OpenvpnMultuTunnel) maintainOverlayRoutes() {
	peer := t.PeerIP()
	local := plainIP(t.OverlayIP())
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	openvpnMultuSyncPeerRoutes(t.workers, local, peer)
	for {
		select {
		case <-t.routeStop:
			return
		case <-ticker.C:
			openvpnMultuSyncPeerRoutes(t.workers, local, peer)
		}
	}
}
