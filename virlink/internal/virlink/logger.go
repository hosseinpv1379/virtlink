// logger.go — structured logging with rate limiting and optional profiling.
//
// Levels: error < warn < info < debug
// Profile reports ([prof]) are independent — enable with [logging] profile = true
//
// Output formats:
//   tty  : colored symbols + aligned columns
//   pipe : "2026-01-02 15:04:05  WRN  message"  (grep-friendly)
//
// isatty() result is cached at first call — no Stat syscall per log line.
// logWarnOnce / logInfoOnce suppress repeated messages within a time window
// so retry loops do not spam the console.
package virlink

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// ── level ────────────────────────────────────────────────────────────────────

type logLevel int

const (
	lvlError logLevel = iota
	lvlWarn
	lvlInfo
	lvlDebug
)

var globalLevel = lvlInfo

func initLogger(cfg *LoggingCfg) {
	switch strings.ToLower(cfg.Level) {
	case "debug":
		globalLevel = lvlDebug
	case "warn", "warning":
		globalLevel = lvlWarn
	case "error":
		globalLevel = lvlError
	default:
		globalLevel = lvlInfo
	}
	initProfiler(&Config{Logging: *cfg})
	initDiagSnap()
}

func levelAllows(min logLevel) bool { return globalLevel >= min }

// ── buffered stdout ───────────────────────────────────────────────────────────

var (
	logOut     = bufio.NewWriterSize(os.Stdout, 4096)
	logOutMu   sync.Mutex
)

func writeLog(s string) {
	logOutMu.Lock()
	_, _ = logOut.WriteString(s)
	_ = logOut.Flush()
	logOutMu.Unlock()
}

// ── isatty (cached) ───────────────────────────────────────────────────────────

var (
	ttyOnce sync.Once
	ttyVal  bool
)

func isatty() bool {
	ttyOnce.Do(func() {
		fi, err := os.Stdout.Stat()
		ttyVal = err == nil && (fi.Mode()&os.ModeCharDevice) != 0
	})
	return ttyVal
}

// ── rate-limited logging ──────────────────────────────────────────────────────

var (
	rateMu   sync.Mutex
	rateSeen = make(map[string]time.Time, 64)
)

// logWarnOnce emits msg at WARN level at most once per window for the given key.
// Use key as a short stable identifier (e.g. "tcp:stream:0") so the same
// message from different call sites stays separate.
func logWarnOnce(key string, window time.Duration, msg string) {
	rateMu.Lock()
	now := time.Now()
	if last, ok := rateSeen[key]; ok && now.Sub(last) < window {
		rateMu.Unlock()
		return
	}
	rateSeen[key] = now
	rateMu.Unlock()
	logWarn(msg)
}

// logInfoOnce emits msg at INFO level at most once per window for the given key.
func logInfoOnce(key string, window time.Duration, msg string) {
	rateMu.Lock()
	now := time.Now()
	if last, ok := rateSeen[key]; ok && now.Sub(last) < window {
		rateMu.Unlock()
		return
	}
	rateSeen[key] = now
	rateMu.Unlock()
	logInfo(msg)
}

// ── public log functions ──────────────────────────────────────────────────────

func logDebug(msg string) {
	if levelAllows(lvlDebug) {
		emit("DBG", msg)
	}
}

func logInfo(msg string) {
	if levelAllows(lvlInfo) {
		emit("INF", msg)
	}
}

func logWarn(msg string) {
	if levelAllows(lvlWarn) {
		emit("WRN", msg)
	}
}

func logError(msg string) {
	emit("ERR", msg)
}

// logProfile emits CPU activity reports (only when profile=true).
func logProfile(msg string) {
	if profEnabled.Load() {
		emit("PRF", msg)
	}
}

// emit is the single output path.
func emit(level, msg string) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	var line string
	if isatty() {
		line = fmt.Sprintf("%s  %s  %s\n", cGray+ts+cReset, levelSym(level), msg)
	} else {
		line = fmt.Sprintf("%s  %s  %s\n", ts, level, msg)
	}
	writeLog(line)
}

func levelSym(level string) string {
	switch level {
	case "INF":
		return cGray + "·" + cReset
	case "WRN":
		return cYellow + "⚠" + cReset
	case "ERR":
		return cRed + cBold + "✗" + cReset
	case "DBG":
		return cCyan + "·" + cReset
	case "PRF":
		return cBlue + "◈" + cReset
	default:
		return level
	}
}

// ── startup banner ────────────────────────────────────────────────────────────

func printBanner(tunnelType, mode, localIP, remoteIP, overlay, peer, iface string,
	probePort, httpPort, benchPort int) {

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
				cGray, k, cReset, cGray, cReset, v)
		}
		row("local", localIP)
		row("peer", remoteIP)
		row("overlay", cCyan+overlay+cReset+" → "+cGreen+peer+cReset)
		row("device", cBold+iface+cReset)
		row("panel", fmt.Sprintf("http://%s:%d/  (health /health  bench /bench)", plainIP(overlay), httpPort))
		row("probe", fmt.Sprintf("UDP :%d  (handshake)", probePort))
		row("bench", fmt.Sprintf("TCP :%d  profile=:%d/profile", benchPort, httpPort))
		fmt.Printf("%s\n\n", cBlue+line+cReset)
	} else {
		ts := time.Now().Format("2006-01-02 15:04:05")
		fields := []string{
			fmt.Sprintf("type=%s  mode=%s", tunnelType, mode),
			fmt.Sprintf("local=%s  peer=%s", localIP, remoteIP),
			fmt.Sprintf("overlay=%s  peer_overlay=%s  dev=%s", overlay, peer, iface),
			fmt.Sprintf("panel=:%d  probe_udp=:%d  bench_tcp=:%d  profile=:%d/profile", httpPort, probePort, benchPort, httpPort),
		}
		for _, f := range fields {
			fmt.Printf("%s  INF  [start] %s\n", ts, f)
		}
	}
}

// ── setup-phase helpers ───────────────────────────────────────────────────────

func step(msg string) {
	if isatty() {
		ts := time.Now().Format("2006-01-02 15:04:05")
		writeLog(fmt.Sprintf("%s  %s  %s %s\n", cGray+ts+cReset, cGray+"·"+cReset, cCyan+"→"+cReset, msg))
	} else {
		emit("INF", "[setup] "+msg)
	}
}

func logOK(msg string) {
	if isatty() {
		ts := time.Now().Format("2006-01-02 15:04:05")
		writeLog(fmt.Sprintf("%s  %s  %s %s\n", cGray+ts+cReset, cGray+"·"+cReset, cGreen+"✓"+cReset, msg))
	} else {
		emit("INF", "[setup] ✓ "+msg)
	}
}

func warn(msg string) { logWarn(msg) }

func header(title string) {
	if isatty() {
		writeLog(fmt.Sprintf("\n%s  virlink %s\n\n", cBlue+"⬡"+cReset, cBold+title+cReset))
	} else {
		emit("INF", "[start] "+title)
	}
}

func done(iface, overlay, peer string, extras ...string) {
	if isatty() {
		ts := time.Now().Format("2006-01-02 15:04:05")
		writeLog(fmt.Sprintf("%s  %s  %s  dev=%s  overlay=%s  peer=%s\n",
			cGray+ts+cReset,
			cGray+"·"+cReset,
			cGreen+cBold+"✓ TUNNEL UP"+cReset,
			cBold+iface+cReset,
			cCyan+overlay+cReset,
			cGreen+peer+cReset))
		for _, e := range extras {
			writeLog(fmt.Sprintf("                         %s\n", cGray+e+cReset))
		}
	} else {
		emit("INF", fmt.Sprintf("[up] dev=%s  overlay=%s  peer=%s", iface, overlay, peer))
		for _, e := range extras {
			emit("INF", "[up] "+e)
		}
	}
}

// ── heartbeat formatting ──────────────────────────────────────────────────────

func fmtHeartbeat(dev, linkState, hsState, lastProbe string,
	rxB, txB, rxPkt, txPkt uint64, uptime time.Duration) string {

	if isatty() {
		lc := cGreen
		if linkState != "UP" {
			lc = cRed
		}
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
	cMagenta = "\033[35m"
)

func color(c, s string) string {
	if !isatty() {
		return s
	}
	return c + s + cReset
}
