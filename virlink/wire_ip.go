// wire_ip.go — IPv4 header build/parse for userspace wire spoofing.
package main

import (
	"encoding/binary"

	"golang.org/x/sys/unix"
)

const udpHdrLen = 8

func putIPv4Header(pkt []byte, src, dst [4]byte, proto byte, totalLen int) {
	pkt[0] = 0x45
	pkt[1] = 0
	binary.BigEndian.PutUint16(pkt[2:], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:], 0) // id
	pkt[6] = 0x40
	pkt[7] = 0
	pkt[8] = 64
	pkt[9] = proto
	pkt[10] = 0
	pkt[11] = 0
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	cs := ipv4Checksum(pkt[:ipHdrLen])
	binary.BigEndian.PutUint16(pkt[10:], cs)
}

func ipv4Checksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		if i == 10 {
			continue
		}
		sum += uint32(hdr[i])<<8 | uint32(hdr[i+1])
	}
	if len(hdr)&1 != 0 {
		sum += uint32(hdr[len(hdr)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func putUDPHeader(hdr []byte, srcPort, dstPort uint16, ulen int) {
	binary.BigEndian.PutUint16(hdr[0:], srcPort)
	binary.BigEndian.PutUint16(hdr[2:], dstPort)
	binary.BigEndian.PutUint16(hdr[4:], uint16(ulen))
	hdr[6] = 0
	hdr[7] = 0
}

func buildWireICMP(frame []byte, src, dst [4]byte, id, seq uint16, payload []byte) []byte {
	icmp := buildICMPFrame(frame[ipHdrLen:], id, seq, payload)
	total := ipHdrLen + len(icmp)
	pkt := frame[:total]
	putIPv4Header(pkt, src, dst, unix.IPPROTO_ICMP, total)
	return pkt
}

func buildWireProto(frame []byte, src, dst [4]byte, proto byte, payload []byte) []byte {
	total := ipHdrLen + len(payload)
	pkt := frame[:total]
	copy(pkt[ipHdrLen:], payload)
	putIPv4Header(pkt, src, dst, proto, total)
	return pkt
}

func buildWireUDP(frame []byte, src, dst [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	off := ipHdrLen + udpHdrLen
	total := off + len(payload)
	pkt := frame[:total]
	copy(pkt[off:], payload)
	putUDPHeader(pkt[ipHdrLen:off], srcPort, dstPort, udpHdrLen+len(payload))
	putIPv4Header(pkt, src, dst, unix.IPPROTO_UDP, total)
	return pkt
}

func openRawHdrIncl(proto int) (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, proto)
	if err != nil {
		return 0, err
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		unix.Close(fd)
		return 0, err
	}
	tuneRawSock(fd)
	return fd, nil
}

// parseIPv4Payload returns inner payload after the IPv4 header.
func parseIPv4Payload(pkt []byte) (ihl int, ok bool) {
	if len(pkt) < ipHdrLen {
		return 0, false
	}
	ihl = int(pkt[0]&0xf) * 4
	if ihl < ipHdrLen || len(pkt) < ihl {
		return 0, false
	}
	return ihl, true
}

func parseUDPInner(pkt []byte) (payload []byte, ok bool) {
	ihl, ok := parseIPv4Payload(pkt)
	if !ok || len(pkt) < ihl+udpHdrLen {
		return nil, false
	}
	if pkt[9] != unix.IPPROTO_UDP {
		return nil, false
	}
	return pkt[ihl+udpHdrLen:], true
}

func acceptWirePeer(sa *unix.SockaddrInet4, local, peer, spoofSrc [4]byte, w wireSpoof) bool {
	if sa == nil {
		return false
	}
	if sa.Addr == local {
		return false
	}
	if w.on && sa.Addr == spoofSrc {
		return false
	}
	return sa.Addr == peer
}
