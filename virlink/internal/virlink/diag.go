// diag.go — actionable tunnel diagnostics (always on, no profile required).
//
// Each heartbeat emits a [diag] line that maps counter deltas to a clear pipeline:
//
//   TX  stack→TUN→wire : tx_read → tx_send  (tx_nodst on server = no peer yet)
//   RX  wire→TUN→stack : rx_recv → rx_write  (rx_drop* / rx_drop_write = why)
//
// Counters in stats.go are always incremented; profile=true only adds the PRF report.
package virlink

import (
	"fmt"
	"strings"
	"time"
)

var diagSnap struct {
	vals [statMax]uint64
	at   time.Time
}

func initDiagSnap() {
	diagSnap.at = time.Now()
	for i := range statCounts {
		diagSnap.vals[i] = statCounts[i].Load()
	}
}

// logDiag prints a grep-friendly diagnostic line at INFO level.
func logDiag(msg string) {
	if !levelAllows(lvlInfo) {
		return
	}
	ts := time.Now().Format("2006-01-02 15:04:05")
	if isatty() {
		writeLog(fmt.Sprintf("%s  %s  %s\n", cGray+ts+cReset, cMagenta+"◆"+cReset, "[diag] "+msg))
	} else {
		writeLog(fmt.Sprintf("%s  INF  [diag] %s\n", ts, msg))
	}
}

// logDiagOnce rate-limits identical diagnostic keys (e.g. repeated tun write errors).
func logDiagOnce(key string, window time.Duration, msg string) {
	logWarnOnce("diag:"+key, window, "[diag] "+msg)
}

type pipeStats struct {
	txRead, txSend, txNoDst       uint64
	rxRecv, rxWrite               uint64
	rxDropPeer, rxDropProto       uint64
	rxDropSeq, rxDrop, rxDropWrt  uint64
	rxPoll, txPoll                uint64
}

func statDelta(id int) uint64 {
	cur := statCounts[id].Load()
	prev := diagSnap.vals[id]
	if cur >= prev {
		return cur - prev
	}
	return cur
}

func snapStat(id int, d *uint64) { *d = statDelta(id) }

func pipeStatsFor(tunnelType string) pipeStats {
	var p pipeStats
	switch tunnelType {
	case "icmp":
		snapStat(statICMPTxRead, &p.txRead)
		snapStat(statICMPTxSend, &p.txSend)
		snapStat(statICMPTxNoDst, &p.txNoDst)
		snapStat(statICMPRxRecv, &p.rxRecv)
		snapStat(statICMPRxWrite, &p.rxWrite)
		snapStat(statICMPRxDropPeer, &p.rxDropPeer)
		snapStat(statICMPRxDropProto, &p.rxDropProto)
		snapStat(statICMPRxDropSeq, &p.rxDropSeq)
		snapStat(statICMPRxDropWrite, &p.rxDropWrt)
		snapStat(statICMPRxPoll, &p.rxPoll)
		snapStat(statICMPTxPoll, &p.txPoll)
	case "udp", "udp-obfs":
		snapStat(statUDPTxRead, &p.txRead)
		snapStat(statUDPTxSend, &p.txSend)
		snapStat(statUDPTxNoDst, &p.txNoDst)
		snapStat(statUDPRxRecv, &p.rxRecv)
		snapStat(statUDPRxWrite, &p.rxWrite)
		snapStat(statUDPRxDrop, &p.rxDrop)
		snapStat(statUDPRxDropWrite, &p.rxDropWrt)
		snapStat(statUDPTxPoll, &p.txPoll)
	case "bip":
		snapStat(statBIPTxRead, &p.txRead)
		snapStat(statBIPTxSend, &p.txSend)
		snapStat(statBIPTxNoDst, &p.txNoDst)
		snapStat(statBIPRxRecv, &p.rxRecv)
		snapStat(statBIPRxWrite, &p.rxWrite)
		snapStat(statBIPRxDrop, &p.rxDrop)
		snapStat(statBIPRxDropWrite, &p.rxDropWrt)
		snapStat(statBIPRxPoll, &p.rxPoll)
		snapStat(statBIPTxPoll, &p.txPoll)
	case "tcp":
		snapStat(statTCPTxRead, &p.txRead)
		snapStat(statTCPTxSend, &p.txSend)
		snapStat(statTCPTxNoConn, &p.txNoDst)
		snapStat(statTCPRxFrame, &p.rxRecv)
		snapStat(statTCPRxWrite, &p.rxWrite)
	case "tcpmux":
		snapStat(statTCPTxRead, &p.txRead)
		snapStat(statTCPTxSend, &p.txSend)
		snapStat(statTCPTxNoConn, &p.txNoDst)
		snapStat(statTCPRxFrame, &p.rxRecv)
		snapStat(statTCPRxWrite, &p.rxWrite)
	default:
		return p
	}
	return p
}

func fmtPipe(n uint64) string {
	if n == 0 {
		return "0"
	}
	return fmtNum(n)
}

func txStage(p pipeStats) string {
	if p.txRead == 0 && p.txSend == 0 && p.txNoDst == 0 {
		return "idle"
	}
	if p.txNoDst > 0 && p.txSend == 0 {
		return fmt.Sprintf("BLOCKED(nodst=%s)", fmtPipe(p.txNoDst))
	}
	if p.txRead > 0 && p.txSend == 0 {
		return fmt.Sprintf("FAIL(read=%s send=0 wire TX error?)", fmtPipe(p.txRead))
	}
	if p.txSend > 0 {
		return fmt.Sprintf("OK(read=%s send=%s)", fmtPipe(p.txRead), fmtPipe(p.txSend))
	}
	return fmt.Sprintf("read=%s send=%s", fmtPipe(p.txRead), fmtPipe(p.txSend))
}

func rxStage(p pipeStats, tunnelType string) string {
	drops := p.rxDropPeer + p.rxDropProto + p.rxDropSeq + p.rxDrop
	if p.rxRecv == 0 && drops == 0 && p.rxWrite == 0 {
		return "idle (nothing from peer on wire)"
	}
	if p.rxRecv == 0 && drops > 0 {
		return fmt.Sprintf("BLOCKED(all %s pkts filtered)", fmtPipe(drops))
	}
	if p.rxRecv > 0 && p.rxWrite == 0 {
		if p.rxDropWrt > 0 {
			return fmt.Sprintf("FAIL(recv=%s tun_write_err=%s)", fmtPipe(p.rxRecv), fmtPipe(p.rxDropWrt))
		}
		return fmt.Sprintf("STUCK(recv=%s write=0 batch not flushing?)", fmtPipe(p.rxRecv))
	}
	if p.rxRecv > 0 && p.rxWrite > 0 {
		extra := ""
		if drops > 0 {
			extra = fmt.Sprintf(" drop=%s", fmtPipe(drops))
		}
		return fmt.Sprintf("OK(recv=%s write=%s%s)", fmtPipe(p.rxRecv), fmtPipe(p.rxWrite), extra)
	}
	_ = tunnelType
	return fmt.Sprintf("recv=%s write=%s", fmtPipe(p.rxRecv), fmtPipe(p.rxWrite))
}

func diagCause(tunnelType, mode, hs string, p pipeStats) string {
	var hints []string

	if mode == "server" && p.txNoDst > 0 && p.txSend == 0 {
		hints = append(hints, "server waiting: client must send first packet so we learn its UDP/ICMP source port")
	}
	if p.txRead > 0 && p.txSend == 0 && p.txNoDst == 0 {
		hints = append(hints, "outbound wire send failing — look for [wire] TX failed; check firewall, rp_filter, run as root")
	}
	if p.rxRecv == 0 && p.txSend > 0 && mode == "client" {
		hints = append(hints, "we send but peer never replies — peer down, wrong remote_ip, or UDP/ICMP blocked inbound on server")
	}
	if p.rxRecv == 0 && p.txSend == 0 && p.txRead == 0 {
		hints = append(hints, "no tunnel traffic — try: ping <peer_overlay>  or check both sides use same tunnel type/port")
	}
	if p.rxDropPeer > 0 {
		hints = append(hints, fmt.Sprintf("%s packets from wrong IP (check remote_ip / [mangle] wire addresses)", fmtPipe(p.rxDropPeer)))
	}
	if p.rxDropProto > 0 && tunnelType == "icmp" {
		hints = append(hints, fmt.Sprintf("%s ICMP not tunnel echo (type≠8 or wrong id 0xCAFE)", fmtPipe(p.rxDropProto)))
	}
	if p.rxDropWrt > 0 {
		hints = append(hints, fmt.Sprintf("%s TUN write errors — kernel rejected injected packets", fmtPipe(p.rxDropWrt)))
	}
	if p.rxRecv > 0 && p.rxWrite > 0 && (hs == "waiting" || hs == "dead" || hs == "degraded") {
		hints = append(hints, "wire RX works but hs stale — overlay probe path broken; wire keepalive should refresh hs on v3.1.2+")
	}
	if p.rxDrop > 0 && tunnelType == "udp" {
		hints = append(hints, fmt.Sprintf("%s UDP filtered (wrong peer IP or local echo)", fmtPipe(p.rxDrop)))
	}

	if len(hints) == 0 {
		if p.rxRecv > 0 && p.rxWrite == 0 {
			return "wire packets received but not injected into TUN — check tun_err counter or upgrade (write fd bug)"
		}
		if hs == "connected" {
			return "pipeline healthy"
		}
		return "no obvious fault in counters — enable logging.level=debug for per-packet detail"
	}
	return strings.Join(hints, "; ")
}

// logTunnelDiag emits one [diag] line per heartbeat with pipeline status and cause.
func logTunnelDiag(tunnelType, mode, hsState string) {
	switch tunnelType {
	case "icmp", "udp", "udp-obfs", "bip", "tcp", "tcpmux":
	default:
		return
	}

	now := time.Now()
	elapsed := now.Sub(diagSnap.at).Seconds()
	if elapsed < 1 {
		elapsed = 1
	}

	p := pipeStatsFor(tunnelType)
	cause := diagCause(tunnelType, mode, hsState, p)

	line := fmt.Sprintf("%s/%s  hs=%s  window=%ds  TX tun→wire: %s  RX wire→tun: %s  → %s",
		tunnelType, mode, hsState, int(elapsed),
		txStage(p), rxStage(p, tunnelType), cause)

	// Drop detail counters when non-zero (helps grep logs).
	var detail []string
	if p.rxDropPeer > 0 {
		detail = append(detail, "drop_peer="+fmtPipe(p.rxDropPeer))
	}
	if p.rxDropProto > 0 {
		detail = append(detail, "drop_proto="+fmtPipe(p.rxDropProto))
	}
	if p.rxDropSeq > 0 {
		detail = append(detail, "drop_seq="+fmtPipe(p.rxDropSeq))
	}
	if p.rxDrop > 0 {
		detail = append(detail, "drop="+fmtPipe(p.rxDrop))
	}
	if p.rxDropWrt > 0 {
		detail = append(detail, "tun_err="+fmtPipe(p.rxDropWrt))
	}
	if p.txNoDst > 0 {
		detail = append(detail, "nodst="+fmtPipe(p.txNoDst))
	}
	if len(detail) > 0 {
		line += "  {" + strings.Join(detail, " ") + "}"
	}

	logDiag(line)

	// Refresh snapshot for next window.
	for i := range statCounts {
		diagSnap.vals[i] = statCounts[i].Load()
	}
	diagSnap.at = now
}
