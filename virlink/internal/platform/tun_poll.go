// tun_poll.go — single-goroutine TUN TX reader (all queues via one poll loop).
//
// Two polling modes:
//
//   Run — shared read buffer (zero pool pressure, caller MUST copy before next read).
//   RunOwned — per-packet pool buffer (caller owns the buffer and must putBuf it).
//              hdrRoom bytes are reserved at the start of each buffer so the caller
//              can write a wire header in-place without an extra copy:
//
//                  payload = buf[hdrRoom : hdrRoom+n]
//                  buf[0:hdrRoom] is zeroed and available for the header.
package platform

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

type tunPoller struct {
	tun     *TunDev
	stop    *StoppedFlag
	pollFds []unix.PollFd
	buf     []byte // shared read buffer for Run(); nil when using RunOwned
	baseMs  int
	idleMs  int
	hdrRoom int // bytes reserved before payload (RunOwned only)
}

// newTunPoller creates a poller with a single shared read buffer (use with Run).
func NewTunPoller(tun *TunDev, stop *StoppedFlag) *tunPoller {
	return NewTunPollerH(tun, stop, 0)
}

// newTunPollerH creates a poller with per-packet owned pool buffers (use with RunOwned).
// hdrRoom bytes are reserved at the start of each buffer for the wire header.
// Pass hdrRoom=0 and use Run for protocols that build headers into a separate frame.
func NewTunPollerH(tun *TunDev, stop *StoppedFlag, hdrRoom int) *tunPoller {
	p := &tunPoller{
		tun:     tun,
		stop:    stop,
		baseMs:  perfPollMs(),
		idleMs:  perfPollMs(),
		hdrRoom: hdrRoom,
	}
	if hdrRoom == 0 {
		// Shared buffer mode: reuse across reads (Run path).
		p.buf = getBuf()
	}
	// Otherwise RunOwned path: no shared buffer, allocate per packet.
	p.pollFds = make([]unix.PollFd, len(tun.fds))
	for i, q := range tun.fds {
		_ = unix.SetNonblock(int(q.Fd()), true)
		p.pollFds[i] = unix.PollFd{Fd: int32(q.Fd()), Events: unix.POLLIN}
	}
	return p
}

func (p *tunPoller) Close() {
	if p.buf != nil {
		putBuf(p.buf)
		p.buf = nil
	}
}

// drainQueue reads all available packets using the shared buffer.
// Called by Run; onPkt must copy payload before returning.
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

// drainQueueOwned reads all available packets using per-packet pool buffers.
// Called by RunOwned; onPkt receives full ownership of buf and must call putBuf.
// payload is at buf[p.hdrRoom : p.hdrRoom+n].
func (p *tunPoller) drainQueueOwned(q *os.File, onPkt func(buf []byte, n int) bool) (got, exit bool) {
	for {
		buf := getBuf()
		// Read TUN packet into the slice starting after the reserved header room.
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
			// Callback signals stop; ownership of buf was transferred.
			return got, true
		}
	}
	return got, false
}

// Run drains ready queue fds, then blocks on poll until data or stop.
// onPkt receives p.buf[:n] — MUST NOT hold the slice after returning.
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

// RunOwned is like Run but allocates a fresh pool buffer per packet.
// onPkt receives the full owned buffer and the payload length (n).
//
//	payload = buf[p.hdrRoom : p.hdrRoom+n]
//	header  = buf[0 : p.hdrRoom]   ← zeroed, caller writes wire header here
//
// onPkt owns buf and MUST eventually call putBuf(buf) (or add it to a batch
// that calls putBuf on flush).  Return false to stop the loop.
func (p *tunPoller) RunOwned(onEmpty func(), onPkt func(buf []byte, n int) bool) {
	idleCap := perfIdleCapMs()
	eager := true
	for !p.stop.stopped() {
		if eager {
			eager = false
			got := false
			for _, q := range p.tun.fds {
				g, exit := p.drainQueueOwned(q, onPkt)
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
					if _, exit := p.drainQueueOwned(p.tun.fds[i], onPkt); exit {
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
