//go:build linux

package main

import (
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const icmpBatchMax = 32

// mmsghdr matches struct mmsghdr on Linux amd64/arm64.
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

func recvmmsg(fd int, msgs []mmsghdr, flags int) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	n, _, e := unix.Syscall6(unix.SYS_RECVMMSG,
		uintptr(fd),
		uintptr(unsafe.Pointer(&msgs[0])),
		uintptr(len(msgs)),
		uintptr(flags), 0, 0)
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
