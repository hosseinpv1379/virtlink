package wire

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

var tcpWirePeerUp atomic.Bool

func resetTcpWireConnectState() { tcpWirePeerUp.Store(false) }

func noteTcpWireConnected() { tcpWirePeerUp.Store(true) }

// tcpConnectStagger staggers stream connection attempts to avoid a SYN storm.
// 100 ms per slot: all streams connected within ~700 ms for 8 streams.
func tcpConnectStagger(slot int) {
	if slot > 0 {
		time.Sleep(time.Duration(slot) * 100 * time.Millisecond)
	}
}

// logTcpStreamRetry logs a stream reconnect attempt at most once per window.
// This prevents log spam when a peer is temporarily unreachable and N streams
// are all retrying every 3 s simultaneously.
func logTcpStreamRetry(label string, slot int, err error) {
	key := fmt.Sprintf("%s:%d", label, slot)
	msg := fmt.Sprintf("[wire] %s stream %d: %v", label, slot, err)

	if tcpWirePeerUp.Load() {
		// Peer was up before — transient drop; suppress after the first notice.
		logWarnOnce(key, 60*time.Second, msg+" — reconnecting")
		return
	}
	if strings.Contains(err.Error(), "connection refused") {
		// Server not ready yet — info, not warn; suppress after first occurrence.
		logInfoOnce(key, 10*time.Second, msg+" — peer not ready yet")
		return
	}
	logWarnOnce(key, 30*time.Second, msg+" — retrying")
}
