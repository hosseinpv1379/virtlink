// tun_poll.go — single-goroutine TUN TX reader (all queues via one poll loop).
//
// Replaces N per-queue goroutines with one poller — fewer threads, lower idle CPU,
// same throughput under load (kernel distributes packets across queue fds).
package virlink

import (
	"errors"
	"os"

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

// drainQueue reads all available packets from one TUN queue fd.
// exit is true when onPkt requests the poller to stop.
func (p *tunPoller) drainQueue(q *os.File, onPkt func(pkt []byte, n int) bool) (got, exit bool) {
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
			return got, true
		}
	}
	return got, false
}

// Run drains ready queue fds, then blocks on poll until data or stop.
// After a poll timeout, skips the all-queue EAGAIN scan and polls again — this
// avoids N×read(EAGAIN) syscalls per idle cycle when tun_queues > 1.
func (p *tunPoller) Run(onEmpty func(), onPkt func(pkt []byte, n int) bool) {
	idleCap := perfIdleCapMs()
	eager := true
	for !p.stop.stopped() {
		if eager {
			eager = false
			got := false
			for _, q := range p.tun.fds {
				g, exit := p.drainQueue(q, onPkt)
				if exit {
					return
				}
				if g {
					got = true
				}
			}
			if got {
				p.idleMs = p.baseMs
				eager = true
				continue
			}
		}
		if onEmpty != nil {
			onEmpty()
		}
		n, _ := unix.Poll(p.pollFds, p.idleMs)
		if n > 0 {
			for i := range p.pollFds {
				if p.pollFds[i].Revents&unix.POLLIN != 0 {
					if _, exit := p.drainQueue(p.tun.fds[i], onPkt); exit {
						return
					}
				}
			}
			p.idleMs = p.baseMs
			eager = true
		} else if p.idleMs < idleCap {
			p.idleMs += p.baseMs
		}
	}
}
