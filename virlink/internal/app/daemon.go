// daemon.go — long-running process lifecycle.
package app

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"

	"virlink/internal/config"
	"virlink/internal/core"
	"virlink/internal/platform"
	"virlink/internal/protocol/amneziawg"
	"virlink/internal/protocol/hysteria2"
	"virlink/internal/protocol/wireguard"
	"virlink/internal/wire"
)

type linkMonitor struct {
	lastHS   string
	lastLink string
	inited   bool
}

func runDaemon(cfg *config.Config, tun core.Tunnel) int {
	platform.InitLogger(&cfg.Logging)
	platform.Header(fmt.Sprintf("%s · %s", cfg.Tunnel.Type, cfg.Tunnel.Mode))

	if err := tun.Up(); err != nil {
		platform.LogError("tunnel up: " + err.Error())
		return 1
	}

	var fwdRules []platform.ForwardRule
	if cfg.Tunnel.Mode == "client" && cfg.Forward.Enabled && len(cfg.Forward.Rules) > 0 {
		var err error
		fwdRules, err = platform.ParseRules(cfg.Forward.Rules)
		if err != nil {
			platform.LogError("forward rules: " + err.Error())
			_ = tun.Down()
			return 1
		}
		platform.ApplyForward(tun.PeerIP(), fwdRules)
	}

	interval := cfg.Transport.HeartbeatInterval
	if interval <= 0 {
		interval = 10
	}
	ivDur := time.Duration(interval) * time.Second
	startedAt := time.Now()

	var hm *platform.HealthMgr
	if !cfg.Health.Disabled {
		hm = platform.NewHealthMgr(startedAt, ivDur)
		hm.Start(core.PlainIP(tun.OverlayIP()), tun.PeerIP(), cfg.Health.Port, cfg.Health.HTTPPort, tun)
	}

	hp := cfg.Health.HTTPPort
	platform.PrintBanner(
		cfg.Tunnel.Type, cfg.Tunnel.Mode,
		cfg.Tunnel.LocalIP, cfg.Tunnel.RemoteIP,
		tun.OverlayIP(), tun.PeerIP(), tun.DevName(),
		cfg.Health.Port, hp, hp+1,
	)

	if len(fwdRules) > 0 {
		parts := make([]string, 0, len(fwdRules))
		for _, r := range fwdRules {
			parts = append(parts, fmt.Sprintf("%d→%d", r.ListenPort, r.TargetPort))
		}
		platform.LogInfo("[fwd] rules: " + strings.Join(parts, "  "))
	}

	var mon linkMonitor

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	stopHB := make(chan struct{})
	go func() {
		ticker := time.NewTicker(ivDur)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				printHeartbeat(tun, startedAt, hm, &mon)
			case <-stopHB:
				return
			}
		}
	}()
	go platform.StartProfileLoop(stopHB)

	sig := <-sigCh
	fmt.Println()
	platform.LogInfo(fmt.Sprintf("signal %s — shutting down", sig))
	close(stopHB)

	if len(fwdRules) > 0 {
		platform.LogInfo("[fwd] removing port forward rules")
		platform.RemoveForward(tun.PeerIP(), fwdRules)
	}

	platform.LogInfo("[down] tearing down tunnel")
	if err := tun.Down(); err != nil {
		platform.LogError("[down] " + err.Error())
		return 1
	}
	platform.LogInfo("[down] done  •  goodbye")
	return 0
}

func printHeartbeat(tun core.Tunnel, since time.Time, hm *platform.HealthMgr, mon *linkMonitor) {
	dev := tun.DevName()

	l, err := netlink.LinkByName(dev)
	if err != nil {
		if mon.lastLink != "MISSING" {
			mon.lastLink = "MISSING"
			platform.LogWarn(fmt.Sprintf("[link] %s interface missing", dev))
		}
		return
	}

	linkState := "UP"
	if l.Attrs().Flags&net.FlagUp == 0 {
		linkState = "DOWN"
	}

	hsState := "unknown"
	if hm != nil {
		hsState = hm.Handshake()
	} else if _, ok := tun.(*hysteria2.Hysteria2Tunnel); ok {
		hsState = "hy2"
	}
	if wg, ok := tun.(*wireguard.WireGuardTunnel); ok {
		if ts, wgOK := wireguard.WireguardLatestHandshake(wg.DevName(), "wg"); wgOK {
			hsState = "connected"
			_ = ts
		} else if hsState == "" || hsState == "waiting" {
			hsState = "waiting"
		}
	}
	if awg, ok := tun.(*amneziawg.AmneziaWGTunnel); ok {
		if ts, ok := wireguard.WireguardLatestHandshake(awg.DevName(), "awg"); ok {
			hsState = "connected"
			_ = ts
		} else if hsState == "" || hsState == "waiting" {
			hsState = "waiting"
		}
	}

	logKey := hsState + "|" + linkState
	if mon.inited && mon.lastHS+"|"+mon.lastLink == logKey {
		return
	}
	prevHS := mon.lastHS
	wasInited := mon.inited
	mon.inited = true
	mon.lastHS = hsState
	mon.lastLink = linkState

	if linkState == "DOWN" {
		if prevHS != "" || wasInited {
			platform.LogWarn(fmt.Sprintf("[link] %s disconnected (interface DOWN)", dev))
		}
		wire.WireLogHeartbeat()
		return
	}

	healthy := hsState == "connected" || hsState == "hy2"

	switch {
	case healthy:
		if !wasInited || (prevHS != hsState && prevHS != "connected" && prevHS != "hy2") {
			platform.LogInfo(fmt.Sprintf("[link] %s connected", dev))
		}
	case hsState == "waiting":
		platform.LogWarn(fmt.Sprintf("[link] %s waiting for peer", dev))
	case hsState == "degraded":
		platform.LogWarn(fmt.Sprintf("[link] %s degraded (packet loss)", dev))
	case hsState == "dead":
		platform.LogError(fmt.Sprintf("[link] %s disconnected (probe timeout)", dev))
	default:
		if prevHS != hsState {
			platform.LogInfo(fmt.Sprintf("[link] %s state=%s", dev, hsState))
		}
	}

	if !healthy {
		wire.WireLogHeartbeat()
	}
}
