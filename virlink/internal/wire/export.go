package wire

// OpenRawWire opens IPPROTO_RAW for userspace wire spoofing TX.
func OpenRawWire() (int, error) { return openRawWire() }

// OpenRawWireRx opens IPPROTO_UDP raw socket for RX (IPPROTO_RAW cannot receive on Linux).
func OpenRawWireRx() (int, error) { return openRawWireRx() }

// WirePeer returns the outer source IP to accept on RX.
func (w WireSpoof) WirePeer(fallback [4]byte) [4]byte { return w.wirePeer(fallback) }

// Src returns the spoofed source IP bytes.
func (w WireSpoof) Src() [4]byte { return w.src }

// Dst returns the expected peer wire source IP bytes.
func (w WireSpoof) Dst() [4]byte { return w.dst }

// TcpConnectStagger sleeps briefly before parallel TCP dials.
func TcpConnectStagger(slot int) { tcpConnectStagger(slot) }

// LogTcpStreamRetry logs a throttled TCP stream retry.
func LogTcpStreamRetry(label string, slot int, err error) { logTcpStreamRetry(label, slot, err) }

// NoteTcpWireConnected marks TCP wire path as connected.
func NoteTcpWireConnected() { noteTcpWireConnected() }

// ResetTcpWireConnectState clears TCP wire connect state.
func ResetTcpWireConnectState() { resetTcpWireConnectState() }

// BuildWireICMP builds a wire ICMP echo frame with optional IPv4 header room in frame.
func BuildWireICMP(frame []byte, src, dst [4]byte, id, seq uint16, payload []byte) []byte {
	return buildWireICMP(frame, src, dst, id, seq, payload)
}

// WireMonitorActive reports whether wire spoof diagnostics are enabled.
func WireMonitorActive() bool { return wireMonitorActive() }

// Ip4Fmt formats a fixed IPv4 address.
func Ip4Fmt(ip [4]byte) string { return ip4Fmt(ip) }

// UdpHdrLen is the UDP header size in bytes.
const UdpHdrLen = udpHdrLen

func BuildWireUDP(frame []byte, src, dst [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	return buildWireUDP(frame, src, dst, srcPort, dstPort, payload)
}

func BuildWireProto(frame []byte, src, dst [4]byte, proto byte, payload []byte) []byte {
	return buildWireProto(frame, src, dst, proto, payload)
}
