// logger.go — structured, human-friendly logging.
//
// Terminal (tty):  colored symbols + aligned columns
// File / pipe  :  plain ISO timestamp + 3-char level tag (grep-friendly)
//
// All paths (setup helpers, heartbeat, daemon) route through printLog
// so log files are 100% uniform.
package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

var globalLogLevel = "info"

func initLogger(level string) {
	if level != "" {
		globalLogLevel = level
	}
}

// ── public log functions ──────────────────────────────────────────────────────

func logDebug(msg string) {
	if globalLogLevel == "debug" {
		printLog("DBG", msg)
	}
}

func logInfo(msg string) {
	if globalLogLevel == "debug" || globalLogLevel == "info" {
		printLog("INF", msg)
	}
}

func logWarn(msg string) {
	printLog("WRN", msg)
}

func logError(msg string) {
	printLog("ERR", msg)
}

// printLog is the single output path.
//
// Plain  (file/pipe): "2026-06-24 19:10:01  INF  message"
// tty:                "2026-06-24 19:10:01  ·    message"  (colored symbols)
func printLog(level, msg string) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	if isatty() {
		var sym string
		switch level {
		case "INF":
			sym = cGray + "·" + cReset
		case "WRN":
			sym = cYellow + "⚠" + cReset
		case "ERR":
			sym = cRed + cBold + "✗" + cReset
		case "DBG":
			sym = cCyan + "·" + cReset
		default:
			sym = level
		}
		fmt.Printf("%s  %s  %s\n", cGray+ts+cReset, sym, msg)
	} else {
		fmt.Printf("%s  %s  %s\n", ts, level, msg)
	}
}

// ── startup banner ────────────────────────────────────────────────────────────

// printBanner prints a framed startup summary.
// tty: Unicode box + colors.  file: plain ASCII.
func printBanner(tunnelType, mode, localIP, remoteIP, overlay, peer, iface string,
	healthPort, benchPort int) {

	if isatty() {
		line := strings.Repeat("━", 54)
		fmt.Printf("\n%s\n", cBlue+line+cReset)
		fmt.Printf("  %s  virlink %s  %s·%s %s%s%s  %s·%s %s%s%s\n",
			cBlue+"⬡"+cReset,
			cBold+"v"+version+cReset,
			cGray, cReset, cCyan, tunnelType, cReset,
			cGray, cReset, cGreen, mode, cReset)
		fmt.Printf("%s\n", cBlue+line+cReset)

		row := func(k, v string) {
			fmt.Printf("  %s%-10s%s  %s│%s  %s\n",
				cGray, k, cReset,
				cGray, cReset,
				v)
		}
		row("local", localIP)
		row("peer", remoteIP)
		row("overlay", cCyan+overlay+cReset+" → "+cGreen+peer+cReset)
		row("device", cBold+iface+cReset)
		row("health", fmt.Sprintf("http://0.0.0.0:%d/", healthPort))
		row("bench", fmt.Sprintf("0.0.0.0:%d (GET /bench)", benchPort))
		fmt.Printf("%s\n\n", cBlue+line+cReset)
	} else {
		// plain log lines (one per field for easy grep)
		ts := time.Now().Format("2006-01-02 15:04:05")
		fields := []string{
			fmt.Sprintf("type=%s  mode=%s", tunnelType, mode),
			fmt.Sprintf("local=%s  peer=%s", localIP, remoteIP),
			fmt.Sprintf("overlay=%s  peer_overlay=%s  dev=%s", overlay, peer, iface),
			fmt.Sprintf("health=:%d  bench=:%d", healthPort, benchPort),
		}
		for _, f := range fields {
			fmt.Printf("%s  INF  [start] %s\n", ts, f)
		}
	}
}

// ── setup-phase helpers (called from tun_*.go Up()) ──────────────────────────

func step(msg string) {
	if isatty() {
		ts := time.Now().Format("2006-01-02 15:04:05")
		fmt.Printf("%s  %s  %s %s\n", cGray+ts+cReset, cGray+"·"+cReset, cCyan+"→"+cReset, msg)
	} else {
		printLog("INF", "[setup] "+msg)
	}
}

func logOK(msg string) {
	if isatty() {
		ts := time.Now().Format("2006-01-02 15:04:05")
		fmt.Printf("%s  %s  %s %s\n", cGray+ts+cReset, cGray+"·"+cReset, cGreen+"✓"+cReset, msg)
	} else {
		printLog("INF", "[setup] ✓ "+msg)
	}
}

func warn(msg string) {
	printLog("WRN", msg)
}

func header(title string) {
	if isatty() {
		fmt.Printf("\n%s  virlink %s\n\n", cBlue+"⬡"+cReset, cBold+title+cReset)
	} else {
		printLog("INF", "[start] "+title)
	}
}

// done is called after tunnel.Up() succeeds.
func done(iface, overlay, peer string, extras ...string) {
	if isatty() {
		ts := time.Now().Format("2006-01-02 15:04:05")
		fmt.Printf("%s  %s  %s  dev=%s  overlay=%s  peer=%s\n",
			cGray+ts+cReset,
			cGray+"·"+cReset,
			cGreen+cBold+"✓ TUNNEL UP"+cReset,
			cBold+iface+cReset,
			cCyan+overlay+cReset,
			cGreen+peer+cReset)
		for _, e := range extras {
			fmt.Printf("                         %s\n", cGray+e+cReset)
		}
	} else {
		printLog("INF", fmt.Sprintf("[up] dev=%s  overlay=%s  peer=%s", iface, overlay, peer))
		for _, e := range extras {
			printLog("INF", "[up] "+e)
		}
	}
}

// ── heartbeat formatting ──────────────────────────────────────────────────────

// fmtHeartbeat builds the heartbeat message string.
// Called by daemon.go printHeartbeat.
func fmtHeartbeat(dev, linkState, hsState, lastProbe string,
	rxB, txB, rxPkt, txPkt uint64, uptime time.Duration) string {

	if isatty() {
		// link color
		lc := cGreen
		if linkState != "UP" {
			lc = cRed
		}
		// handshake color
		hc := cGray
		switch hsState {
		case "connected":
			hc = cGreen
		case "degraded":
			hc = cYellow
		case "dead":
			hc = cRed
		}
		probe := ""
		if lastProbe != "" && lastProbe != "never" {
			probe = "  " + cGray + "probe=" + lastProbe + cReset
		}
		return fmt.Sprintf(
			"%s %-10s  link=%-4s  hs=%-9s  %s%-10s%s(%spkt)  %s%-10s%s(%spkt)  up=%s%s",
			cGreen+"♥"+cReset,
			cBold+dev+cReset,
			lc+linkState+cReset,
			hc+hsState+cReset,
			cCyan+"↓"+cReset, fmtBytes(rxB), cGray, fmtNum(rxPkt),
			cBlue+"↑"+cReset, fmtBytes(txB), cGray, fmtNum(txPkt),
			uptime.Round(time.Second),
			probe,
		)
	}
	// plain (file)
	probe := ""
	if lastProbe != "" {
		probe = "  probe=" + lastProbe
	}
	return fmt.Sprintf(
		"♥  dev=%-10s  link=%-4s  hs=%-9s  ↓%s(%spkt)  ↑%s(%spkt)  up=%s%s",
		dev, linkState, hsState,
		fmtBytes(rxB), fmtNum(rxPkt),
		fmtBytes(txB), fmtNum(txPkt),
		uptime.Round(time.Second),
		probe,
	)
}

// ── color constants ───────────────────────────────────────────────────────────

const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cGray   = "\033[90m"
	cRed    = "\033[31m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cBlue   = "\033[34m"
	cCyan   = "\033[36m"
)

func isatty() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func color(c, s string) string {
	if !isatty() {
		return s
	}
	return c + s + cReset
}
