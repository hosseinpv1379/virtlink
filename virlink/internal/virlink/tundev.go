// tundev.go — TUN device helpers (single + multi-queue).
//
// IFF_MULTI_QUEUE gives N file descriptors for the same interface.
// The kernel load-balances outbound packets (stack → userspace) across
// queues, so N parallel txLoop goroutines can read at N× the rate of one.
// Falls back to a single queue when the kernel rejects multi-queue.
//
// Wire→TUN injection uses a dedicated write queue fd (writeFd). The TX poller
// sets the read queue fds O_NONBLOCK; O_NONBLOCK is per file-description, so a
// dup() of a read fd would also become non-blocking and TUN writes return
// EAGAIN — the exact "rx_recv>0 rx_write=0" failure mode.
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

// TunDev holds read queue fds (poller) and a separate blocking writeFd (RX inject).
type TunDev struct {
	fds     []*os.File // read queues only — poller sets these O_NONBLOCK
	writeFd *os.File   // dedicated queue, never read, never O_NONBLOCK
	queues  int        // number of read queues
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

// openTunMultiTry opens readQueues read fds + 1 dedicated write-only queue fd.
// Queue 0 is the write fd (kernel always accepts inject on the primary queue);
// queues 1..N are read-only for the TX poller (O_NONBLOCK, never written).
func openTunMultiTry(name string, readQueues int) (*TunDev, error) {
	if readQueues < 1 {
		readQueues = 1
	}
	// +1 queue: q0 = wire→TUN inject (blocking), q1.. = stack→userspace read.
	totalQ := readQueues + 1
	td := &TunDev{
		fds:    make([]*os.File, 0, readQueues),
		queues: readQueues,
	}
	useMQ := totalQ > 1
	for i := 0; i < totalQ; i++ {
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
		f := os.NewFile(uintptr(fd), fmt.Sprintf("%s-q%d", name, i))
		if i == 0 {
			td.writeFd = f
		} else {
			td.fds = append(td.fds, f)
		}
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
