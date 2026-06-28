package virlink

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

var tcpWirePeerUp atomic.Bool

func resetTcpWireConnectState() { tcpWirePeerUp.Store(false) }

func noteTcpWireConnected() { tcpWirePeerUp.Store(true) }

func tcpConnectStagger(slot int) {
	if slot > 0 {
		time.Sleep(time.Duration(slot) * 400 * time.Millisecond)
	}
}

func logTcpStreamRetry(label string, slot int, err error) {
	msg := fmt.Sprintf("[wire] %s stream %d: %v", label, slot, err)
	if tcpWirePeerUp.Load() {
		logDebug(msg + " — retry")
		return
	}
	if strings.Contains(err.Error(), "connection refused") {
		logInfo(msg + " — peer not ready yet")
		return
	}
	logWarn(msg + " — retry in 3s")
}
