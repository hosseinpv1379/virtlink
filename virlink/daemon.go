// daemon.go — long-running process lifecycle.
//
// Flow:
//   1. tun.Up()          ← build tunnel inside the kernel (via netlink)
//   2. heartbeat loop    ← read netlink stats every N seconds, print status
//   3. SIGINT / SIGTERM  ← tun.Down() removes all kernel objects, then exit
//
// The tunnel only exists while this process is alive.
package main

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

// runDaemon brings up the tunnel and blocks until interrupted.
// Returns an exit code (0 = clean, 1 = error).
func runDaemon(cfg *Config, tun Tunnel) int {
	initLogger(cfg.Logging.Level)

	logInfo(fmt.Sprintf("starting virlink  type=%s  mode=%s  local=%s  peer=%s",
		cfg.Tunnel.Type, cfg.Tunnel.Mode, cfg.LocalIP, cfg.RemoteIP))

	// ── 1. bring up the tunnel (netlink operations) ───────────────────────────
	if err := tun.Up(); err != nil {
		logError("tunnel up: " + err.Error())
		return 1
	}
	logInfo(fmt.Sprintf("tunnel ready  dev=%s  overlay=%s  peer=%s",
		tun.DevName(), tun.OverlayIP(), tun.PeerIP()))

	// ── 2. port forwarding (client-only, iptables DNAT) ───────────────────────
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

	// ── 3. health probe + HTTP endpoint ───────────────────────────────────────
	interval := cfg.Transport.HeartbeatInterval
	if interval <= 0 {
		interval = 10
	}
	ivDur := time.Duration(interval) * time.Second
	startedAt := time.Now()

	var hm *HealthMgr
	if !cfg.Health.Disabled {
		hm = NewHealthMgr(startedAt, ivDur)
		hm.Start(plainIP(tun.OverlayIP()), tun.PeerIP(), cfg.Health.Port, tun)
		logInfo(fmt.Sprintf("health probe active  port=%d  probe_interval=%ds",
			cfg.Health.Port, interval))
	}

	// ── 4. register signal handler ────────────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// ── 5. heartbeat goroutine ────────────────────────────────────────────────
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

	// ── 6. wait for signal ────────────────────────────────────────────────────
	sig := <-sigCh
	fmt.Println()
	logInfo(fmt.Sprintf("received %s — shutting down...", sig))
	close(stopHB)

	// ── 7. remove forward rules ───────────────────────────────────────────────
	if len(fwdRules) > 0 {
		logInfo("removing port forward rules...")
		RemoveForward(tun.PeerIP(), fwdRules)
	}

	// ── 8. tear down tunnel ───────────────────────────────────────────────────
	logInfo("tearing down tunnel...")
	if err := tun.Down(); err != nil {
		logError("teardown: " + err.Error())
		return 1
	}

	logInfo("done  goodbye")
	return 0
}

// ── heartbeat ─────────────────────────────────────────────────────────────────

func printHeartbeat(tun Tunnel, fwdRules []ForwardRule, since time.Time, hm *HealthMgr) {
	dev := tun.DevName()
	uptime := time.Since(since).Round(time.Second)

	l, err := netlink.LinkByName(dev)
	if err != nil {
		logWarn(fmt.Sprintf("dev=%-12s  NOT FOUND  uptime=%s", dev, uptime))
		return
	}

	// link state
	linkState := "UP"
	linkColor := cGreen
	if l.Attrs().Flags&net.FlagUp == 0 {
		linkState = "DOWN"
		linkColor = cRed
	}

	// rx/tx stats from kernel (netlink)
	var rxB, txB, rxPkt, txPkt uint64
	if s := l.Attrs().Statistics; s != nil {
		rxB, txB = s.RxBytes, s.TxBytes
		rxPkt, txPkt = s.RxPackets, s.TxPackets
	}

	// handshake state
	hsStr := "disabled"
	hsColor := cGray
	lastSeenStr := ""
	if hm != nil {
		hsStr = hm.Handshake()
		hsColor = hm.HandshakeColor()
		lastSeenStr = "  last_probe=" + hm.LastSeenStr()
	}

	// forward rules summary
	fwdStr := ""
	if len(fwdRules) > 0 {
		parts := make([]string, 0, len(fwdRules))
		for _, r := range fwdRules {
			parts = append(parts, fmt.Sprintf("%d→%d", r.ListenPort, r.TargetPort))
		}
		fwdStr = "  fwd=[" + strings.Join(parts, " ") + "]"
	}

	logInfo(fmt.Sprintf("♥  dev=%-10s  link=%-4s  handshake=%-9s  rx=%-10s(%spkt)  tx=%-10s(%spkt)  uptime=%s%s%s",
		dev,
		color(linkColor, linkState),
		color(hsColor, hsStr),
		fmtBytes(rxB), fmtNum(rxPkt),
		fmtBytes(txB), fmtNum(txPkt),
		uptime,
		lastSeenStr,
		fwdStr,
	))
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
