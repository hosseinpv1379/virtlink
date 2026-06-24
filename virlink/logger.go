// logger.go — structured timestamped logging.
// All output goes through printLog so log files have a consistent format.
package main

import (
	"fmt"
	"os"
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
		printLog("DBG", msg, cCyan)
	}
}

func logInfo(msg string) {
	if globalLogLevel == "debug" || globalLogLevel == "info" {
		printLog("INF", msg, "")
	}
}

func logWarn(msg string) {
	printLog("WRN", msg, cYellow)
}

func logError(msg string) {
	printLog("ERR", msg, cRed)
}

// printLog writes a timestamped line to stdout (captured by systemd / log file).
// Format (plain, no terminal):  2006-01-02 15:04:05  INF  message
// Format (terminal):            2006-01-02 15:04:05  \033[36mDBG\033[0m  message
func printLog(level, msg, clr string) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	if clr != "" && isatty() {
		fmt.Printf("%s  %s%s%s  %s\n", ts, clr, level, cReset, msg)
	} else {
		fmt.Printf("%s  %s  %s\n", ts, level, msg)
	}
}

// ── setup-phase helpers (tun_*.go Up()) ──────────────────────────────────────
// All route through printLog so log files are uniform.

func step(msg string) {
	printLog("INF", "  setup  "+msg, cCyan)
}

func logOK(msg string) {
	printLog("INF", "  ok     "+msg, cGreen)
}

func warn(msg string) {
	printLog("WRN", msg, cYellow)
}

func header(title string) {
	printLog("INF", "════ virlink: "+title+" ════", cBold)
}

func done(iface, overlay, peer string, extras ...string) {
	printLog("INF", fmt.Sprintf("tunnel UP   dev=%-12s overlay=%-18s peer=%s", iface, overlay, peer), cGreen)
	for _, e := range extras {
		printLog("INF", "            "+e, "")
	}
}

// ── color helpers ─────────────────────────────────────────────────────────────

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
