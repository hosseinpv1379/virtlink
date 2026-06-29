package wire

import (
	"fmt"
	"net"
	"os"
	"time"
)

func ipTo4(s string) [4]byte {
	var out [4]byte
	ip := net.ParseIP(s)
	if ip == nil {
		return out
	}
	copy(out[:], ip.To4())
	return out
}

func wireLogOK(msg string)    { fmt.Fprintf(os.Stdout, "  ✓ %s\n", msg) }
func wireLogWarn(msg string)  { fmt.Fprintf(os.Stderr, "  WRN %s\n", msg) }
func wireLogDebug(msg string) { _ = msg }

func logInfo(msg string) { wireLogOK(msg) }

func logInfoOnce(key string, window time.Duration, msg string) { wireLogOK(msg) }

func logWarnOnce(key string, window time.Duration, msg string) { wireLogWarn(msg) }
