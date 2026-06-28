//go:build linux

package virlink

import (
	"os/exec"
	"regexp"
	"strconv"
)

var nftCounterRe = regexp.MustCompile(`counter name (\S+) packets (\d+)`)

func readWireNFTCounters() (inPeer, outPackets uint64, ok bool) {
	out, err := exec.Command("nft", "list", "table", "ip", nftMangleTable).CombinedOutput()
	if err != nil {
		return 0, 0, false
	}
	for _, m := range nftCounterRe.FindAllStringSubmatch(string(out), -1) {
		if len(m) != 3 {
			continue
		}
		n, _ := strconv.ParseUint(m[2], 10, 64)
		switch m[1] {
		case "vlk_wire_in_peer":
			inPeer = n
		case "vlk_wire_out":
			outPackets = n
		}
	}
	return inPeer, outPackets, true
}
