//go:build !linux

package virlink

import "net"

// tuneTCPConnForce is the non-Linux fallback for TCP buffer tuning.
// On Linux this is replaced by SO_RCVBUFFORCE/SO_SNDBUFFORCE (batch_linux.go).
func tuneTCPConnForce(tc *net.TCPConn) {
	_ = tc.SetReadBuffer(perfSockBuf())
	_ = tc.SetWriteBuffer(perfSockBuf())
}
