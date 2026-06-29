//go:build !linux

package wire

func logWireNFTStatus() {}

func readWireNFTCounters() (inPeer, outPackets uint64, ok bool) {
	return 0, 0, false
}
