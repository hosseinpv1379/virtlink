//go:build linux

package main

import (
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const icmpBatchMax = maxPerfBatch

type mmsghdr struct {
	Hdr unix.Msghdr
	Len uint32
	_   [4]byte
}

func sendmmsg(fd int, msgs []mmsghdr) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	n, _, e := unix.Syscall6(unix.SYS_SENDMMSG,
		uintptr(fd),
		uintptr(unsafe.Pointer(&msgs[0])),
		uintptr(len(msgs)), 0, 0, 0)
	if e != 0 {
		return 0, e
	}
	return int(n), nil
}

func tunWritev(fd *os.File, bufs [][]byte) error {
	if len(bufs) == 0 {
		return nil
	}
	if len(bufs) == 1 {
		_, err := fd.Write(bufs[0])
		return err
	}
	_, err := unix.Writev(int(fd.Fd()), bufs)
	return err
}

// icmpTxBatch holds up to icmpBatchMax frames ready for sendmmsg.
type icmpTxBatch struct {
	n      int
	frames [icmpBatchMax][]byte
	lens   [icmpBatchMax]int
	iovs   [icmpBatchMax]unix.Iovec
	addrs  [icmpBatchMax]unix.RawSockaddrInet4
	msgs   [icmpBatchMax]mmsghdr
}

func (b *icmpTxBatch) reset() { b.n = 0 }

func (b *icmpTxBatch) add(frame []byte, pktLen int, dst [4]byte) {
	i := b.n
	b.frames[i] = frame
	b.lens[i] = pktLen
	b.addrs[i] = unix.RawSockaddrInet4{Family: unix.AF_INET, Addr: dst}
	b.iovs[i].Base = &frame[0]
	b.iovs[i].Len = uint64(pktLen)
	b.msgs[i].Hdr.Name = (*byte)(unsafe.Pointer(&b.addrs[i]))
	b.msgs[i].Hdr.Namelen = unix.SizeofSockaddrInet4
	b.msgs[i].Hdr.Iov = &b.iovs[i]
	b.msgs[i].Hdr.Iovlen = 1
	b.n++
}

// icmpSendBatch sends batched ICMP frames; falls back to Sendto per packet.
func icmpSendBatch(rawFd int, b *icmpTxBatch) {
	if b.n == 0 {
		return
	}
	sent, err := sendmmsg(rawFd, b.msgs[:b.n])
	if err != nil {
		sent = 0
	}
	for i := sent; i < b.n; i++ {
		sa := &unix.SockaddrInet4{Addr: b.addrs[i].Addr}
		_ = unix.Sendto(rawFd, b.frames[i][:b.lens[i]], 0, sa)
	}
}
