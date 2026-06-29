// tun_bip.go — BIP tunnel (IPv4 protocol 58).
//
// Performance: multi-queue TUN, sendmmsg TX batching, tuned raw socket buffers.
package virlink

import (
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	bipSubnet = "10.20.44.0/24"
	bipProto  = 58
)

type BipTunnel struct {
	cfg     *Config
	tun     *TunDev
	rawFd   int
	lockFd  *os.File
	done    chan struct{}
	stop    stoppedFlag
	lastSrc atomic.Value
	wire    wireSpoof
	peerIP  [4]byte
	localIP [4]byte
}

func (t *BipTunnel) DevName() string   { return tunnelDevName(t.cfg, "bip-tun0") }
func (t *BipTunnel) OverlayIP() string { return overlayAddr(t.cfg, bipSubnet) }
func (t *BipTunnel) PeerIP() string    { return peerAddr(t.cfg, bipSubnet) }

func (t *BipTunnel) Up() error {
	c := t.cfg
	dev := t.DevName()
	addr := t.OverlayIP()
	peer := t.PeerIP()
	mtu := c.Tunnel.MTU
	if mtu == 0 {
		mtu = 1480
	}
	t.peerIP = ipTo4(c.RemoteIP)
	t.localIP = ipTo4(c.LocalIP)
	t.wire = wireSpoofFrom(c)
	if c.Mode == "server" {
		t.lastSrc.Store(t.peerIP)
	}

	header("bip / " + c.Mode)
	applyPerfFromConfig(c)
	step("perf: " + perfSummary())
	t.doClean()
	t.stop.reset()

	var err error
	t.lockFd, err = acquireTunnelLock(dev)
	if err != nil {
		return err
	}

	t.tun, err = openTunMulti(dev, perfTunQueues())
	if err != nil {
		return fmt.Errorf("tun: %w", err)
	}
	l, _ := netlink.LinkByName(dev)
	netlink.LinkSetMTU(l, mtu)
	a, _ := netlink.ParseAddr(addr)
	netlink.AddrAdd(l, a)
	netlink.LinkSetUp(l)
	logOK(fmt.Sprintf("%s  %s  queues=%d", dev, addr, t.tun.QueueCount()))

	step(fmt.Sprintf("tuning (%s)...", tuningModeLabel(c)))
	applyTunnelTuning(c, dev)

	if t.wire.on {
		t.rawFd, err = openRawWire()
	} else {
		t.rawFd, err = unix.Socket(unix.AF_INET, unix.SOCK_RAW, bipProto)
	}
	if err != nil {
		return fmt.Errorf("SOCK_RAW proto=%d: %w", bipProto, err)
	}
	tuneRawSock(t.rawFd)
	_ = unix.SetNonblock(t.rawFd, true)
	logOK(fmt.Sprintf("raw proto=%d ready", bipProto))
	logWireSpoof(t.cfg, t.wire)

	addMSS(c, dev)
	t.done = make(chan struct{})

	rawFd := t.rawFd
	go t.rxLoop(rawFd, t.tun.WriteFd())
	go t.txPollLoop(rawFd)

	done(dev, addr, peer,
		fmt.Sprintf("proto : IPv4 proto %d  poller×1", bipProto),
		"test  : ping -c3 "+peer,
	)
	return nil
}

func (t *BipTunnel) rxLoop(rawFd int, tun *os.File) {
	var rb rxMmsgBatch
	rb.init(perfBatchSize())
	defer rb.release()

	peer := t.wire.wirePeer(t.peerIP)
	local := t.localIP
	pollMs := perfPollMs()
	idleMs := pollMs
	bsz := perfBatchSize()
	batch := newTunRxBatch(bsz)

	flush := func() {
		written, total, err := batch.flush(tun)
		reportTunRxFlush(written, total, err, statBIPRxWrite, statBIPRxDropWrite, "bip:tun_write", "BIP", &t.stop)
	}
	defer flush()

	for {
		got, err := rb.recv(rawFd)
		if got == 0 {
			if t.stop.stopped() {
				return
			}
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == nil {
				flush()
				statInc(statBIPRxPoll)
				_ = pollFD(rawFd, unix.POLLIN, idleMs)
				idleMs = idleBackoff(idleMs, pollMs)
				continue
			}
			if err == unix.EINTR {
				continue
			}
			logWarn("bip rx: " + err.Error())
			continue
		}
		idleMs = pollMs
		for i := 0; i < got; i++ {
			pkt := rb.data(i)
			sa := rb.from4(i)
			if !acceptWirePeer(pkt, sa, local, peer, t.wire.src, t.wire, bipProto) {
				statInc(statBIPRxDrop)
				continue
			}
			inner, ok := parseWireInner(pkt, t.wire.on)
			if !ok || len(inner) == 0 {
				continue
			}
			if t.cfg.Mode == "server" {
				t.lastSrc.Store(rememberPeerRoute(t.wire, sa.Addr, t.peerIP))
			}
			statInc(statBIPRxRecv)
			logInfoOnce("tunnel:wire:rx", 24*time.Hour, "first valid packet from peer on wire (RX path OK)")
			batch.add(inner)
		}
		if batch.len() > 0 {
			flush()
		}
	}
}

func (t *BipTunnel) txPollLoop(rawFd int) {
	poller := newTunPoller(t.tun, &t.stop)
	defer poller.close()

	var batch icmpTxBatch
	bsz := perfBatchSize()
	var lastDst [4]byte
	var lastPLen int

	flush := func() {
		if batch.n == 0 {
			return
		}
		statAdd(statBIPTxSend, uint64(batch.n))
		nerr := mmsgSendBatch(rawFd, &batch)
		if t.wire.on {
			sent := batch.n - nerr
			if sent < 0 {
				sent = 0
			}
			wireMon.noteTxBatch(sent, nerr, t.wire.src, lastDst, bipProto, lastPLen)
		} else if nerr > 0 {
			noteWireTxErr(nerr)
		}
		for i := 0; i < batch.n; i++ {
			putBuf(batch.frames[i])
			batch.frames[i] = nil
		}
		batch.reset()
	}

	poller.Run(
		func() {
			statInc(statBIPTxPoll)
			if batch.n > 0 {
				flush()
			}
		},
		func(pkt []byte, n int) bool {
			statInc(statBIPTxRead)
			var routeDst [4]byte
			if t.cfg.Mode == "client" {
				routeDst = t.peerIP
			} else if v := t.lastSrc.Load(); v != nil {
				routeDst = v.([4]byte)
			} else {
				statInc(statBIPTxNoDst)
				if t.wire.on {
					wireMon.noteTxNoDst()
				}
				return true
			}
			frame := getBuf()
			var out []byte
			if t.wire.on {
				out = buildWireProto(frame, t.wire.src, routeDst, bipProto, pkt[:n])
			} else {
				out = frame[:n]
				copy(out, pkt[:n])
			}
			batch.add(frame, len(out), routeDst, 0)
			lastDst = routeDst
			lastPLen = n
			if batch.n >= bsz {
				flush()
			}
			return !t.stop.stopped()
		},
	)
	flush()
}

func (t *BipTunnel) Down() error {
	t.doClean()
	logOK("bip tunnel torn down")
	return nil
}

func (t *BipTunnel) doClean() {
	restoreTunnelTuning()
	t.stop.stop()
	if t.done != nil {
		close(t.done)
		t.done = nil
	}
	if t.rawFd > 0 {
		unix.Close(t.rawFd)
		t.rawFd = 0
	}
	if t.tun != nil {
		t.tun.Close()
		t.tun = nil
	}
	releaseTunnelLock(t.lockFd)
	t.lockFd = nil
	delMSS(t.DevName())
	nlDown(t.DevName())
}

func (t *BipTunnel) Status() {
	if l, err := netlink.LinkByName(t.DevName()); err == nil {
		fmt.Printf("  %s: flags=%v\n", l.Attrs().Name, l.Attrs().Flags)
	}
}
