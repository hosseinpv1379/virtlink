//go:build !linux

package virlink

func readWireNFTCounters() (inPeer, outPackets uint64, ok bool) {
	return 0, 0, false
}
