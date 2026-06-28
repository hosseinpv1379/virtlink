// daemon.go — long-running process lifecycle.
//
// Flow:
//   1. tun.Up()          ← build tunnel inside the kernel (via netlink)
//   2. printBanner()     ← pretty startup summary
//   3. heartbeat loop    ← netlink stats every N seconds
//   4. SIGINT / SIGTERM  ← tun.Down() removes all kernel objects, then exit
package virlink

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
)

func runDaemon(cfg *Config, tun Tunnel) int {
	initLogger(&cfg.Logging)
	header(fmt.Sprintf("%s · %s", cfg.Tunnel.Type, cfg.Tunnel.Mode))

	// ── 1. bring up the tunnel ────────────────────────────────────────────────
	if err := tun.Up(); err != nil {
		logError("tunnel up: " + err.Error())
		return 1
	}

	// ── 2. port forwarding (client-only) ──────────────────────────────────────
	var fwdRules []ForwardRule
	if cfg.Tunnel.Mode == "client" && cfg.Forward.Enabled && len(cfg.Forward.Rules) > 0 {
		var err error
		fwdRules, err = parseRules(cfg.Forward.Rules)
		if err != nil {
			logError("forward rules: " + err.Error())
			_ = tun.Down()
			return 1
		}
		ApplyForward(tun.PeerIP(), fwdRules)
	}

	// ── 3. health probe + HTTP + bench server ─────────────────────────────────
	interval := cfg.Transport.HeartbeatInterval
	if interval <= 0 {
		interval = 10
	}
	ivDur := time.Duration(interval) * time.Second
	startedAt := time.Now()

	var hm *HealthMgr
	if !cfg.Health.Disabled {
		hm = NewHealthMgr(startedAt, ivDur)
		hm.Start(plainIP(tun.OverlayIP()), tun.PeerIP(), cfg.Health.Port, cfg.Health.HTTPPort, tun)
	}

	// ── 4. startup banner ─────────────────────────────────────────────────────
	hp := cfg.Health.HTTPPort
	printBanner(
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
		logInfo("[fwd] rules: " + strings.Join(parts, "  "))
	}

	// ── 5. signal handler ────────────────────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// ── 6. heartbeat + CPU profiler ───────────────────────────────────────────
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
	go startProfileLoop(stopHB)

	// ── 7. wait ───────────────────────────────────────────────────────────────
	sig := <-sigCh
	fmt.Println()
	logInfo(fmt.Sprintf("signal %s — shutting down", sig))
	close(stopHB)

	if len(fwdRules) > 0 {
		logInfo("[fwd] removing port forward rules")
		RemoveForward(tun.PeerIP(), fwdRules)
	}

	logInfo("[down] tearing down tunnel")
	if err := tun.Down(); err != nil {
		logError("[down] " + err.Error())
		return 1
	}
	logInfo("[down] done  •  goodbye")
	return 0
}

// ── heartbeat ─────────────────────────────────────────────────────────────────

func printHeartbeat(tun Tunnel, fwdRules []ForwardRule, since time.Time, hm *HealthMgr) {
	dev := tun.DevName()
	uptime := time.Since(since)

	l, err := netlink.LinkByName(dev)
	if err != nil {
		logWarn(fmt.Sprintf("[♥] dev=%s NOT FOUND  uptime=%s", dev, uptime.Round(time.Second)))
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
	} else if _, ok := tun.(*Hysteria2Tunnel); ok {
		hsState = "hy2"
		lastProbe = "n/a (check hysteria2 log)"
	}
	if wg, ok := tun.(*WireGuardTunnel); ok {
		dev := wg.DevName()
		if ts, wgOK := wireguardLatestHandshake(dev, "wg"); wgOK {
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
	if awg, ok := tun.(*AmneziaWGTunnel); ok {
		dev := awg.DevName()
		if ts, ok := wireguardLatestHandshake(dev, "awg"); ok {
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

	msg := fmtHeartbeat(dev, linkState, hsState, lastProbe,
		rxB, txB, rxPkt, txPkt, uptime)
	logInfo(msg)
}

// ── formatting helpers ────────────────────────────────────────────────────────

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
