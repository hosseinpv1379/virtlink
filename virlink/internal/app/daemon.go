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
		cfg.LocalIP, cfg.RemoteIP,
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

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	stopHB := make(chan struct{})
	go func() {
		ticker := time.NewTicker(ivDur)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				printHeartbeat(tun, fwdRules, startedAt, hm)
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

func printHeartbeat(tun core.Tunnel, fwdRules []platform.ForwardRule, since time.Time, hm *platform.HealthMgr) {
	dev := tun.DevName()
	uptime := time.Since(since)

	l, err := netlink.LinkByName(dev)
	if err != nil {
		platform.LogWarn(fmt.Sprintf("[♥] dev=%s NOT FOUND  uptime=%s", dev, uptime.Round(time.Second)))
		return
	}

	linkState := "UP"
	if l.Attrs().Flags&net.FlagUp == 0 {
		linkState = "DOWN"
	}

	var rxB, txB, rxPkt, txPkt uint64
	if s := l.Attrs().Statistics; s != nil {
		rxB, txB = s.RxBytes, s.TxBytes
		rxPkt, txPkt = s.RxPackets, s.TxPackets
	}

	hsState := ""
	lastProbe := ""
	if hm != nil {
		hsState = hm.Handshake()
		lastProbe = hm.LastSeenStr()
	} else if _, ok := tun.(*hysteria2.Hysteria2Tunnel); ok {
		hsState = "hy2"
		lastProbe = "n/a (check hysteria2 log)"
	}
	if wg, ok := tun.(*wireguard.WireGuardTunnel); ok {
		dev := wg.DevName()
		if ts, wgOK := wireguard.WireguardLatestHandshake(dev, "wg"); wgOK {
			wgAge := time.Since(ts).Round(time.Second).String()
			if hsState == "" || hsState == "waiting" {
				hsState = "wg-ok"
			}
			lastProbe = "wg " + wgAge + " ago"
		} else if hsState == "" || hsState == "waiting" {
			hsState = "wg-wait"
			lastProbe = "no wg handshake"
		}
	}
	if awg, ok := tun.(*amneziawg.AmneziaWGTunnel); ok {
		dev := awg.DevName()
		if ts, ok := wireguard.WireguardLatestHandshake(dev, "awg"); ok {
			wgAge := time.Since(ts).Round(time.Second).String()
			if hsState == "" || hsState == "waiting" {
				hsState = "awg-ok"
			}
			lastProbe = "awg " + wgAge + " ago"
		} else if hsState == "" || hsState == "waiting" {
			hsState = "awg-wait"
			lastProbe = "no awg handshake"
		}
	}

	msg := platform.FmtHeartbeat(dev, linkState, hsState, lastProbe,
		rxB, txB, rxPkt, txPkt, uptime)
	platform.LogInfo(msg)
	wire.WireLogHeartbeat()
}

func fmtBytes(b uint64) string {
	switch {
	case b < 1024:
		return fmt.Sprintf("%dB", b)
	case b < 1024*1024:
		return fmt.Sprintf("%.1fKB", float64(b)/1024)
	case b < 1024*1024*1024:
		return fmt.Sprintf("%.2fMB", float64(b)/1024/1024)
	default:
		return fmt.Sprintf("%.2fGB", float64(b)/1024/1024/1024)
	}
}

func fmtNum(n uint64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	} else if n < 1_000_000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	}
	return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
}
