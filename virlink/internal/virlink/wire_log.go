// wire_log.go — diagnostics for [mangle] wire IP spoof (userspace + nftables).
package virlink

import (
	"fmt"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

type wirePathKind string

const (
	wirePathUserspace wirePathKind = "userspace"
	wirePathKernel    wirePathKind = "kernel"
	wirePathTCPSock   wirePathKind = "tcp-socket"
)

type wirePeerVerdict int

const (
	wirePeerOK wirePeerVerdict = iota
	wirePeerShort
	wirePeerBadProto
	wirePeerSelfLocal
	wirePeerSelfSpoof
	wirePeerWrongSrc
	wirePeerNonIPv4
)

func (v wirePeerVerdict) String() string {
	switch v {
	case wirePeerOK:
		return "ok"
	case wirePeerShort:
		return "short_pkt"
	case wirePeerBadProto:
		return "bad_proto"
	case wirePeerSelfLocal:
		return "self_local"
	case wirePeerSelfSpoof:
		return "self_spoof"
	case wirePeerWrongSrc:
		return "wrong_peer_src"
	case wirePeerNonIPv4:
		return "non_ipv4_from"
	default:
		return "unknown"
	}
}

// WireMonitor tracks outer (wire) packets when [mangle] is enabled.
type WireMonitor struct {
	on   atomic.Bool
	path atomic.Value // wirePathKind

	txOK, txFail atomic.Uint64
	rxOK         atomic.Uint64
	rxDrop       [8]atomic.Uint64

	lastTxAt atomic.Int64 // unix nano
	lastRxAt atomic.Int64

	firstTxLogged atomic.Bool
	firstRxLogged atomic.Bool

	// rate-limit sample drop logs
	dropLogCount atomic.Uint64

	expectPeerWire atomic.Value // string
	txOuterDesc    atomic.Value // string
}

var wireMon WireMonitor

func initWireMonitor(cfg *Config, path wirePathKind) {
	if !wireSpoofEnabled(cfg) {
		return
	}
	wireMon.on.Store(true)
	wireMon.path.Store(path)

	expect := cfg.Mangle.DstIP
	var txDesc string
	switch path {
	case wirePathTCPSock:
		if cfg.Mode == "server" {
			port := cfg.Transport.Port
			if port == 0 {
				port = 8443
			}
			txDesc = fmt.Sprintf("listen :%d  expect client wire src=%s", port, cfg.Mangle.DstIP)
		} else {
			txDesc = fmt.Sprintf("bind src=%s  dial dst=%s (real remote)",
				cfg.Mangle.SrcIP, cfg.RemoteIP)
		}
	default:
		txDesc = fmt.Sprintf("src=%s dst=%s (real remote %s)",
			cfg.Mangle.SrcIP, cfg.RemoteIP, cfg.RemoteIP)
	}
	wireMon.expectPeerWire.Store(expect)
	wireMon.txOuterDesc.Store(txDesc)

	logInfo(fmt.Sprintf("[wire] ── spoof diagnostics (%s) ──", path))
	logInfo(fmt.Sprintf("[wire] role=%s  tunnel=%s  local=%s  remote=%s",
		cfg.Mode, cfg.Tunnel.Type, cfg.LocalIP, cfg.RemoteIP))
	logInfo(fmt.Sprintf("[wire] TX outer: %s", txDesc))
	logInfo(fmt.Sprintf("[wire] RX expect outer src=%s (peer [mangle] srcip)", expect))
	logInfo(fmt.Sprintf("[wire] verify on server: tcpdump -ni any host %s or host %s -vv",
		cfg.LocalIP, cfg.RemoteIP))
	if path == wirePathKernel {
		logInfo("[wire] nft counters: nft list table ip " + nftMangleTable)
	}
	warnWireSpoofPrereqs()
}

func wireMonitorActive() bool { return wireMon.on.Load() }

func ip4Fmt(b [4]byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

func evalWirePeer(pkt []byte, sa *unix.SockaddrInet4, local, expectPeerSrc, ourSpoofSrc [4]byte, w wireSpoof, wantProto byte) (wirePeerVerdict, [4]byte, [4]byte) {
	var zeroSrc, zeroDst [4]byte
	if !w.on {
		if sa == nil {
			return wirePeerNonIPv4, zeroSrc, zeroDst
		}
		if sa.Addr == local {
			return wirePeerSelfLocal, sa.Addr, zeroDst
		}
		if sa.Addr != expectPeerSrc {
			return wirePeerWrongSrc, sa.Addr, zeroDst
		}
		return wirePeerOK, sa.Addr, zeroDst
	}
	_, ok := parseIPv4Payload(pkt)
	if !ok {
		return wirePeerShort, zeroSrc, zeroDst
	}
	var src, dst [4]byte
	copy(src[:], pkt[12:16])
	copy(dst[:], pkt[16:20])
	if wantProto != 0 && pkt[9] != wantProto {
		return wirePeerBadProto, src, dst
	}
	if src == local {
		return wirePeerSelfLocal, src, dst
	}
	if src == ourSpoofSrc {
		return wirePeerSelfSpoof, src, dst
	}
	if src != expectPeerSrc {
		return wirePeerWrongSrc, src, dst
	}
	return wirePeerOK, src, dst
}

func acceptWirePeer(pkt []byte, sa *unix.SockaddrInet4, local, peer, spoofSrc [4]byte, w wireSpoof, wantProto byte) bool {
	v, src, dst := evalWirePeer(pkt, sa, local, peer, spoofSrc, w, wantProto)
	if v == wirePeerOK {
		if wireMonitorActive() {
			wireMon.noteRxOK(src)
		}
		return true
	}
	if wireMonitorActive() {
		wireMon.noteRxDrop(v, src, dst)
	}
	return false
}

func (m *WireMonitor) noteTxBatch(sent, failed int, src, dst [4]byte, proto byte, samplePayload int) {
	if !m.on.Load() {
		return
	}
	if sent > 0 {
		m.txOK.Add(uint64(sent))
		m.lastTxAt.Store(time.Now().UnixNano())
		if m.firstTxLogged.CompareAndSwap(false, true) {
			logInfo(fmt.Sprintf("[wire] first TX outer %s → %s proto=%d (%d B inner)",
				ip4Fmt(src), ip4Fmt(dst), proto, samplePayload))
		}
	}
	if failed > 0 {
		m.txFail.Add(uint64(failed))
		noteWireTxErr(failed)
	}
}

func (m *WireMonitor) noteRxOK(outerSrc [4]byte) {
	m.rxOK.Add(1)
	m.lastRxAt.Store(time.Now().UnixNano())
	if m.firstRxLogged.CompareAndSwap(false, true) {
		expect, _ := m.expectPeerWire.Load().(string)
		logInfo(fmt.Sprintf("[wire] first RX outer src=%s (expect %s) — peer reachable on wire",
			ip4Fmt(outerSrc), expect))
	}
}

func (m *WireMonitor) noteRxDrop(v wirePeerVerdict, src, dst [4]byte) {
	if int(v) < len(m.rxDrop) {
		m.rxDrop[v].Add(1)
	}
	n := m.dropLogCount.Add(1)
	if n <= 8 || n%100 == 0 {
		expect, _ := m.expectPeerWire.Load().(string)
		logWarn(fmt.Sprintf("[wire] RX drop %s  outer src=%s dst=%s  want src=%s",
			v, ip4Fmt(src), ip4Fmt(dst), expect))
	}
}

func (m *WireMonitor) noteTxNoDst() {
	if m.on.Load() {
		logWarn("[wire] TX skipped: no peer route yet (server waiting for first RX?)")
	}
}

// wireLogHeartbeat emits a periodic wire summary (call from daemon heartbeat).
func wireLogHeartbeat() {
	if !wireMon.on.Load() {
		return
	}
	tx := wireMon.txOK.Load()
	txFail := wireMon.txFail.Load()
	rx := wireMon.rxOK.Load()
	wrong := wireMon.rxDrop[wirePeerWrongSrc].Load()
	self := wireMon.rxDrop[wirePeerSelfLocal].Load() + wireMon.rxDrop[wirePeerSelfSpoof].Load()
	proto := wireMon.rxDrop[wirePeerBadProto].Load()

	lastRx := "never"
	if t := wireMon.lastRxAt.Load(); t > 0 {
		lastRx = time.Since(time.Unix(0, t)).Round(time.Second).String() + " ago"
	}

	path, _ := wireMon.path.Load().(wirePathKind)
	line := fmt.Sprintf("[wire] ↑tx=%d (fail=%d)  ↓rx=%d  last_rx=%s  drops wrong_src=%d self=%d bad_proto=%d",
		tx, txFail, rx, lastRx, wrong, self, proto)

	if nftIn, nftOut, ok := readWireNFTCounters(); ok {
		line += fmt.Sprintf("  nft_in=%d nft_out=%d", nftIn, nftOut)
		if path == wirePathKernel {
			if nftOut > 0 && nftIn == 0 {
				line += "  ⚠ mangle OUT hits but IN=0 — peer packets not reaching host IP layer"
			}
		}
	}
	logInfo(line)

	if tx > 0 && rx == 0 && wireMon.lastRxAt.Load() == 0 {
		logWarn("[wire] TX>0 but RX=0 — client sending but server not receiving (firewall, rp_filter, wrong remote_ip, or peer down)")
	} else if tx > 10 && wireMon.lastRxAt.Load() > 0 {
		if age := time.Since(time.Unix(0, wireMon.lastRxAt.Load())); age > 30*time.Second && tx > wireMon.rxOK.Load() {
			logWarn(fmt.Sprintf("[wire] no peer RX for %s while TX active — one-way path broken?", age.Round(time.Second)))
		}
	}
}
