// tun_poll.go — single-goroutine TUN TX reader (all queues via one poll loop).
//
// fds[0] stays blocking (same fd as WriteFd for wire→TUN inject). It is
// never SetNonblock — only read when poll/FIONREAD says data is waiting.
// fds[1..] are SetNonblock and drained in a loop.
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
	hdrRoom int
}

func newTunPoller(tun *TunDev, stop *stoppedFlag) *tunPoller {
	return newTunPollerH(tun, stop, 0)
}

func newTunPollerH(tun *TunDev, stop *stoppedFlag, hdrRoom int) *tunPoller {
	p := &tunPoller{
		tun:     tun,
		stop:    stop,
		baseMs:  perfPollMs(),
		idleMs:  perfPollMs(),
		hdrRoom: hdrRoom,
	}
	if hdrRoom == 0 {
		p.buf = getBuf()
	}
	p.pollFds = make([]unix.PollFd, len(tun.fds))
	for i, q := range tun.fds {
		// q0 is WriteFd — must stay blocking; q1.. are read-only aux queues.
		if i > 0 {
			_ = unix.SetNonblock(int(q.Fd()), true)
		}
		p.pollFds[i] = unix.PollFd{Fd: int32(q.Fd()), Events: unix.POLLIN}
	}
	return p
}

func (p *tunPoller) close() {
	if p.buf != nil {
		putBuf(p.buf)
		p.buf = nil
	}
}

func (p *tunPoller) queueBlocking(qIdx int) bool {
	return qIdx == 0
}

func (p *tunPoller) drainQueue(q *os.File, qIdx int, onPkt func(pkt []byte, n int) bool) (got, exit bool) {
	if p.queueBlocking(qIdx) {
		n, err := q.Read(p.buf)
		if err != nil || n == 0 {
			if err != nil && !p.stop.stopped() {
				logWarn("tun read: " + err.Error())
			}
			return false, false
		}
		if !onPkt(p.buf[:n], n) {
			return true, true
		}
		return true, false
	}
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

func (p *tunPoller) drainQueueOwned(q *os.File, qIdx int, onPkt func(buf []byte, n int) bool) (got, exit bool) {
	if p.queueBlocking(qIdx) {
		buf := getBuf()
		n, err := q.Read(buf[p.hdrRoom:])
		if err != nil || n == 0 {
			putBuf(buf)
			if err != nil && !p.stop.stopped() {
				logWarn("tun read: " + err.Error())
			}
			return false, false
		}
		if !onPkt(buf, n) {
			return true, true
		}
		return true, false
	}
	for {
		buf := getBuf()
		n, err := tunReadNB(q, buf[p.hdrRoom:])
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			putBuf(buf)
			break
		}
		if err != nil || n == 0 {
			putBuf(buf)
			if err != nil && !p.stop.stopped() {
				logWarn("tun read: " + err.Error())
			}
			break
		}
		got = true
		if !onPkt(buf, n) {
			return got, true
		}
	}
	return got, false
}

func (p *tunPoller) Run(onEmpty func(), onPkt func(pkt []byte, n int) bool) {
	idleCap := perfIdleCapMs()
	eager := true
	for !p.stop.stopped() {
		if eager {
			eager = false
			got := false
			for i, q := range p.tun.fds {
				if p.queueBlocking(i) {
					continue // q0 only read after poll reports POLLIN
				}
				g, exit := p.drainQueue(q, i, onPkt)
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
					if _, exit := p.drainQueue(p.tun.fds[i], i, onPkt); exit {
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

func (p *tunPoller) RunOwned(onEmpty func(), onPkt func(buf []byte, n int) bool) {
	idleCap := perfIdleCapMs()
	eager := true
	for !p.stop.stopped() {
		if eager {
			eager = false
			got := false
			for i, q := range p.tun.fds {
				if p.queueBlocking(i) {
					continue
				}
				g, exit := p.drainQueueOwned(q, i, onPkt)
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
					if _, exit := p.drainQueueOwned(p.tun.fds[i], i, onPkt); exit {
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
