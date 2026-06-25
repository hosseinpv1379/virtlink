// tun_poll.go — single-goroutine TUN TX reader (all queues via one poll loop).
//
// Replaces N per-queue goroutines with one poller — fewer threads, lower idle CPU,
// same throughput under load (kernel distributes packets across queue fds).
package virlink

import (
	"errors"

	"golang.org/x/sys/unix"
)

type tunPoller struct {
	tun     *TunDev
	stop    *stoppedFlag
	pollFds []unix.PollFd
	buf     []byte
	baseMs  int
	idleMs  int
}

func newTunPoller(tun *TunDev, stop *stoppedFlag) *tunPoller {
	p := &tunPoller{
		tun:    tun,
		stop:   stop,
		buf:    getBuf(),
		baseMs: perfPollMs(),
		idleMs: perfPollMs(),
	}
	p.pollFds = make([]unix.PollFd, len(tun.fds))
	for i, q := range tun.fds {
		_ = unix.SetNonblock(int(q.Fd()), true)
		p.pollFds[i] = unix.PollFd{Fd: int32(q.Fd()), Events: unix.POLLIN}
	}
	return p
}

func (p *tunPoller) close() { putBuf(p.buf) }

// Run drains all ready queue fds, then blocks on poll until data or stop.
// onEmpty is called before each blocking poll (stats). onPkt returns false to exit.
func (p *tunPoller) Run(onEmpty func(), onPkt func(pkt []byte, n int) bool) {
	for !p.stop.stopped() {
		got := false
		for _, q := range p.tun.fds {
			for {
				n, err := tunReadNB(q, p.buf)
				if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
					break
				}
				if err != nil || n == 0 {
					if err != nil && !p.stop.stopped() {
						logWarn("tun read: " + err.Error())
					}
					break
				}
				got = true
				if !onPkt(p.buf[:n], n) {
					return
				}
			}
		}
		if got {
			p.idleMs = p.baseMs
			continue
		}
		if onEmpty != nil {
			onEmpty()
		}
		_, _ = unix.Poll(p.pollFds, p.idleMs)
		if p.idleMs < 50 {
			p.idleMs += p.baseMs
		}
	}
}
