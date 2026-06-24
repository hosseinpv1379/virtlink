// logger.go — structured timestamped logging.
package main

import (
	"fmt"
	"os"
	"time"
)

// global log level (set from [logging] level in config)
var globalLogLevel = "info"

func initLogger(level string) {
	if level != "" {
		globalLogLevel = level
	}
}

// ── public log functions ──────────────────────────────────────────────────────

func logDebug(msg string) {
	if globalLogLevel == "debug" {
		printLog("DEBUG", msg, cCyan)
	}
}

func logInfo(msg string) {
	if globalLogLevel == "debug" || globalLogLevel == "info" {
		printLog("INFO ", msg, "")
	}
}

func logWarn(msg string) {
	printLog("WARN ", msg, cYellow)
}

func logError(msg string) {
	printLog("ERROR", msg, cRed)
}

func printLog(level, msg, clr string) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	if clr != "" && isatty() {
		fmt.Printf("%s  %s%s%s  %s\n", ts, clr, level, cReset, msg)
	} else {
		fmt.Printf("%s  %s  %s\n", ts, level, msg)
	}
}

// ── setup-phase pretty helpers (used inside tun_*.go during Up()) ─────────────

func step(msg string) {
	fmt.Printf("  %s %s\n", color(cCyan, "▸"), msg)
}

func logOK(msg string) {
	fmt.Printf("  %s %s\n", color(cGreen, "✓"), msg)
}

func warn(msg string) {
	fmt.Fprintf(os.Stderr, "  %s %s\n", color(cYellow, "⚠"), msg)
}

func header(title string) {
	fmt.Printf("\n%s\n\n", color(cBold, "══ virlink: "+title+" ══"))
}

func done(iface, overlay, peer string, extras ...string) {
	fmt.Printf("\n  %s\n", color(cGreen, "✅  tunnel is up"))
	fmt.Printf("     interface  : %s\n", iface)
	fmt.Printf("     overlay IP : %s\n", overlay)
	fmt.Printf("     peer IP    : %s\n", peer)
	for _, e := range extras {
		fmt.Printf("     %s\n", e)
	}
	fmt.Println()
}

// ── color helpers (also used by runner.go) ────────────────────────────────────

const (
	cReset  = "\033[0m"
	cGreen  = "\033[32m"
	cRed    = "\033[31m"
	cYellow = "\033[33m"
	cCyan   = "\033[36m"
	cBold   = "\033[1m"
	cGray   = "\033[90m"
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
