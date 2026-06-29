// tundev.go — TUN device helpers (single + multi-queue).
//
// IFF_MULTI_QUEUE opens N fds for the same interface. The kernel spreads
// stack→userspace packets across all N queues — every fd must be polled.
// Wire→TUN inject writes to fds[0]; tunWrite() retries EAGAIN with POLLOUT
// so O_NONBLOCK on the read poller does not break injection.
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

// TunDev holds N queue fds for one TUN interface.
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
	t.fds = nil
}

func (t *TunDev) Fd0() *os.File { return t.fds[0] }

// WriteFd returns fds[0] for wire→TUN injection.
func (t *TunDev) WriteFd() *os.File { return t.fds[0] }

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
	if n < 1 {
		n = 1
	}
	td := &TunDev{
		fds:    make([]*os.File, 0, n),
		queues: n,
	}
	useMQ := n > 1
	for i := 0; i < n; i++ {
		fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err != nil {
			td.Close()
			return nil, fmt.Errorf("open /dev/net/tun: %w", err)
		}
		var ifr [40]byte
		copy(ifr[:16], name)
		flags := unix.IFF_TUN | unix.IFF_NO_PI
		if useMQ {
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
	if len(pkt) == 0 {
		return nil
	}
	rawFd := int(fd.Fd())
	pfd := []unix.PollFd{{Fd: int32(rawFd), Events: unix.POLLOUT}}
	for attempt := 0; attempt < 256; attempt++ {
		_, err := unix.Write(rawFd, pkt)
		if err == nil {
			return nil
		}
		if err == unix.EINTR {
			continue
		}
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			_, _ = unix.Poll(pfd, 50)
			continue
		}
		return err
	}
	return unix.EAGAIN
}

func tunReadNB(fd *os.File, buf []byte) (int, error) {
	n, err := fd.Read(buf)
	if err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			return 0, unix.EAGAIN
		}
	}
	return n, err
}

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
