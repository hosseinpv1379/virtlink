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
type TunDev struct {
	fds    []*os.File
	queues int
}

func (t *TunDev) Close() {
	for _, f := range t.fds {
		if f != nil {
			f.Close()
		}
	}
}

func (t *TunDev) Fd0() *os.File { return t.fds[0] }

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
	if l, err := netlink.LinkByName(name); err == nil {
		_ = netlink.LinkSetTxQLen(l, perfTxQLen())
	}
	return td, nil
}

func tunWrite(fd *os.File, pkt []byte) error {
	return tunWriteOne(int(fd.Fd()), pkt)
}

// tunWriteOne injects one packet into the TUN device.
//
// The TX poller sets the TUN queue fds non-blocking (for reads), and the RX
// loop writes to the same fd, so a write can return EAGAIN when the kernel's
// TUN rx queue is momentarily full. Instead of dropping the packet (which left
// the overlay with rx_write=0 and the handshake stuck on "waiting"), we wait
// for the fd to become writable and retry. Empty packets are skipped so a
// zero-length datagram never turns into a no-op "successful" write.
func tunWriteOne(rawFd int, pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	pfd := []unix.PollFd{{Fd: int32(rawFd), Events: unix.POLLOUT}}
	for attempt := 0; attempt < 1024; attempt++ {
		_, err := unix.Write(rawFd, pkt)
		if err == nil {
			return nil
		}
		if err == unix.EINTR {
			continue
		}
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			// Wait up to 100 ms for the TUN to drain, then retry.
			_, _ = unix.Poll(pfd, 100)
			continue
		}
		return err
	}
	return unix.EAGAIN
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
