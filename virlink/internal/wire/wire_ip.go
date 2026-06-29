// wire_ip.go — IPv4 header build/parse for userspace wire spoofing.
package wire

import (
	"encoding/binary"

	"golang.org/x/sys/unix"
)

const udpHdrLen = 8

// trimIPv4Packet clips a raw RX buffer to the IPv4 total length field.
func trimIPv4Packet(pkt []byte) []byte {
	if len(pkt) < ipHdrLen || pkt[0]>>4 != 4 {
		return pkt
	}
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if total >= ipHdrLen && total <= len(pkt) {
		return pkt[:total]
	}
	return pkt
}

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

func buildICMPFrame(frame []byte, id, seq uint16, payload []byte) []byte {
	const icmpHdrLen = 8
	n := icmpHdrLen + len(payload)
	pkt := frame[:n]
	pkt[0] = 8
	pkt[1] = 0
	pkt[2] = 0
	pkt[3] = 0
	binary.BigEndian.PutUint16(pkt[4:], id)
	binary.BigEndian.PutUint16(pkt[6:], seq)
	copy(pkt[8:], payload)
	cs := icmpChecksum(pkt)
	binary.BigEndian.PutUint16(pkt[2:], cs)
	return pkt
}

func icmpChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)&1 != 0 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func tuneRawSock(fd int) {
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 32<<20)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 32<<20)
}

func parseIPv4Payload(pkt []byte) (ihl int, ok bool) {
	return ParseIPv4Payload(pkt)
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

// openRawWire opens IPPROTO_RAW for TX: sends complete IPv4 packets with IP_HDRINCL.
func openRawWire() (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return 0, err
	}
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, 15, 1) // IP_FREEBIND (linux)
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, 19, 1) // IP_TRANSPARENT (linux)
	tuneRawSock(fd)
	return fd, nil
}

// openRawWireRx opens IPPROTO_UDP raw socket for RX.
// IPPROTO_RAW never receives on Linux; IPPROTO_UDP is required to receive UDP packets.
func openRawWireRx() (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_UDP)
	if err != nil {
		return 0, err
	}
	tuneRawSock(fd)
	return fd, nil
}

// parseWireInner returns the payload after the IPv4 header for wire (IPPROTO_RAW)
// receives, or the packet body when the kernel already stripped the IP header.
func ParseWireInner(pkt []byte, wireOn bool) (inner []byte, ok bool) {
	if wireOn {
		ihl, ok := parseIPv4Payload(pkt)
		if !ok || len(pkt) <= ihl {
			return nil, false
		}
		return pkt[ihl:], true
	}
	if len(pkt) >= ipHdrLen && pkt[0]>>4 == 4 {
		if ihl, ok := parseIPv4Payload(pkt); ok && len(pkt) > ihl {
			return pkt[ihl:], true
		}
	}
	if len(pkt) == 0 {
		return nil, false
	}
	return pkt, true
}

// parseIPv4Payload returns inner payload after the IPv4 header.
func ParseIPv4Payload(pkt []byte) (ihl int, ok bool) {
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
