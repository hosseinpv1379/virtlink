// tundev.go — TUN device helpers (single + multi-queue).
//
// IFF_MULTI_QUEUE gives N file descriptors for the same interface.
// The kernel load-balances outbound packets (stack → userspace) across
// queues, so N parallel txLoop goroutines can read at N× the rate of one.
// Falls back to a single queue when the kernel rejects multi-queue.
package virlink

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	tunSetIff = uintptr(0x400454ca)
)

// TunDev holds one or more TUN queue file descriptors.
// writeFd is a blocking dup of queue 0 used only for wire→TUN injection (RX loops).
// The TX poller sets the queue fds non-blocking for reads; sharing the same fd for
// writes caused EAGAIN drops and unreliable POLLOUT polling on the TUN char device.
type TunDev struct {
	fds     []*os.File
	writeFd *os.File
	queues  int
}

func (t *TunDev) Close() {
	if t.writeFd != nil {
		t.writeFd.Close()
		t.writeFd = nil
	}
	for _, f := range t.fds {
		if f != nil {
			f.Close()
		}
	}
}

func (t *TunDev) Fd0() *os.File { return t.fds[0] }

// WriteFd returns the blocking fd for injecting packets into the TUN (RX path).
func (t *TunDev) WriteFd() *os.File {
	if t.writeFd != nil {
		return t.writeFd
	}
	return t.fds[0]
}

func (t *TunDev) QueueCount() int {
	if t == nil {
		return 0
	}
	return t.queues
}

func openTunDev(name string) (*os.File, error) {
	td, err := openTunMulti(name, 1)
	if err != nil {
		return nil, err
	}
	return td.fds[0], nil
}

func openTunMulti(name string, n int) (*TunDev, error) {
	if n < 1 {
		n = 1
	}
	td, err := openTunMultiTry(name, n)
	if err != nil && n > 1 {
		warn(fmt.Sprintf("multi-queue TUN unavailable (%v) — falling back to 1 queue", err))
		return openTunMultiTry(name, 1)
	}
	return td, err
}

func openTunMultiTry(name string, n int) (*TunDev, error) {
	td := &TunDev{fds: make([]*os.File, 0, n), queues: n}
	for i := 0; i < n; i++ {
		fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err != nil {
			td.Close()
			return nil, fmt.Errorf("open /dev/net/tun: %w", err)
		}
		var ifr [40]byte
		copy(ifr[:16], name)
		flags := unix.IFF_TUN | unix.IFF_NO_PI
		if n > 1 {
			flags |= unix.IFF_MULTI_QUEUE
		}
		*(*uint16)(unsafe.Pointer(&ifr[16])) = uint16(flags)
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
			tunSetIff, uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
			unix.Close(fd)
			td.Close()
			return nil, fmt.Errorf("TUNSETIFF %s q%d: %w", name, i, errno)
		}
		td.fds = append(td.fds, os.NewFile(uintptr(fd), fmt.Sprintf("%s-q%d", name, i)))
	}
	if len(td.fds) > 0 {
		wfd, err := unix.Dup(int(td.fds[0].Fd()))
		if err != nil {
			td.Close()
			return nil, fmt.Errorf("dup tun write fd: %w", err)
		}
		td.writeFd = os.NewFile(uintptr(wfd), name+"-write")
	}
	if l, err := netlink.LinkByName(name); err == nil {
		_ = netlink.LinkSetTxQLen(l, perfTxQLen())
	}
	return td, nil
}

func tunWrite(fd *os.File, pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	rawFd := int(fd.Fd())
	for {
		_, err := unix.Write(rawFd, pkt)
		if err == nil {
			return nil
		}
		if err == unix.EINTR {
			continue
		}
		return err
	}
}

// tunReadNB reads one packet from a non-blocking TUN fd.
// Returns (0, EAGAIN) when no data is available.
func tunReadNB(fd *os.File, buf []byte) (int, error) {
	n, err := fd.Read(buf)
	if err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			return 0, unix.EAGAIN
		}
	}
	return n, err
}

// pollFD waits until fd is readable/writable or timeoutMs elapses.
func pollFD(fd int, events int16, timeoutMs int) error {
	fds := []unix.PollFd{{Fd: int32(fd), Events: events}}
	for {
		_, err := unix.Poll(fds, timeoutMs)
		if err == unix.EINTR {
			continue
		}
		return err
	}
}
