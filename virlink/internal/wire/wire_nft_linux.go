//go:build linux

package wire

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

var nftCounterRes = []*regexp.Regexp{
	regexp.MustCompile(`counter name (\S+) packets (\d+)`),
	regexp.MustCompile(`(?m)counter (\S+) \{\s*packets (\d+)`),
	regexp.MustCompile(`(?m)counter (\S+) packets (\d+)`),
}

func readWireNFTCounters() (inPeer, outPackets uint64, ok bool) {
	out, err := exec.Command("nft", "list", "table", "ip", nftMangleTable).CombinedOutput()
	if err != nil {
		return 0, 0, false
	}
	text := string(out)
	for _, re := range nftCounterRes {
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			if len(m) != 3 {
				continue
			}
			n, _ := strconv.ParseUint(m[2], 10, 64)
			switch m[1] {
			case "vlk_wire_in_peer":
				if n > inPeer {
					inPeer = n
				}
			case "vlk_wire_out":
				if n > outPackets {
					outPackets = n
				}
			}
		}
	}
	return inPeer, outPackets, strings.Contains(text, nftMangleTable)
}

func logWireNFTStatus() {
	in, out, ok := readWireNFTCounters()
	if !ok {
		wireLogWarn("[wire] nft table " + nftMangleTable + " not loaded — relay inactive")
		return
	}
	wireLogOK(fmt.Sprintf("[wire] nft relay loaded  counters in=%d out=%d  (nft list table ip %s)",
		in, out, nftMangleTable))
}
