//go:build linux

package virlink

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

const tunFIONREAD = 0x541B // linux FIONREAD

// tunPending returns bytes waiting on a TUN fd (0 if none / error).
func tunPending(fd int) int {
	var n int32
	_, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), tunFIONREAD, uintptr(unsafe.Pointer(&n)))
	if err != 0 {
		return 0
	}
	return int(n)
}
