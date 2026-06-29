// tun_bip.go — BIP tunnel (IPv4 protocol 58).
//
// Performance: multi-queue TUN, sendmmsg TX batching, tuned raw socket buffers.
package bip

import (
	"virlink/internal/wire"
	"virlink/internal/platform"
	"virlink/internal/core"
	"virlink/internal/config"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	bipSubnet = "10.20.44.0/24"
	bipProto  = 58
)

type BipTunnel struct {
	cfg     *config.Config
	tun     *platform.TunDev
	rawFd   int
	lockFd  *os.File
	done chan struct{}
	stop    platform.StoppedFlag
	lastSrc atomic.Value
	wire    wire.WireSpoof
	peerIP  [4]byte
	localIP [4]byte
}

func (t *BipTunnel) DevName() string   { return platform.TunnelDevName(t.cfg, "bip-tun0") }
func (t *BipTunnel) OverlayIP() string { return core.OverlayAddr(t.cfg, bipSubnet) }
func (t *BipTunnel) PeerIP() string    { return core.PeerAddr(t.cfg, bipSubnet) }

func (t *BipTunnel) Up() error {
	c := t.cfg
	dev := t.DevName()
	addr := t.OverlayIP()
	peer := t.PeerIP()
	mtu := c.Tunnel.MTU
	if mtu == 0 {
		mtu = 1480
	}
	t.peerIP = platform.IpTo4(c.RemoteIP)
	t.localIP = platform.IpTo4(c.LocalIP)
	t.wire = wire.WireSpoofFrom(c)
	if c.Mode == "server" {
		t.lastSrc.Store(t.peerIP)
	}

	platform.Header("bip / " + c.Mode)
	platform.ApplyPerfFromConfig(c)
	platform.Step("perf: " + platform.PerfSummary())
	t.doClean()
	t.stop.Reset()

	var err error
	t.lockFd, err = platform.AcquireTunnelLock(dev)
	if err != nil {
		return err
	}

	t.tun, err = platform.OpenTunMulti(dev, platform.PerfTunQueues())
	if err != nil {
		return fmt.Errorf("tun: %w", err)
	}
	l, _ := netlink.LinkByName(dev)
	netlink.LinkSetMTU(l, mtu)
	a, _ := netlink.ParseAddr(addr)
	netlink.AddrAdd(l, a)
	netlink.LinkSetUp(l)
	platform.LogOK(fmt.Sprintf("%s  %s  queues=%d", dev, addr, t.tun.QueueCount()))

	platform.Step(fmt.Sprintf("tuning (%s)...", platform.TuningModeLabel(c)))
	platform.ApplyTunnelTuning(c, dev)

	if t.wire.On {
		t.rawFd, err = wire.OpenRawWire()
	} else {
		t.rawFd, err = unix.Socket(unix.AF_INET, unix.SOCK_RAW, bipProto)
	}
	if err != nil {
		return fmt.Errorf("SOCK_RAW proto=%d: %w", bipProto, err)
	}
	platform.TuneRawSock(t.rawFd)
	_ = unix.SetNonblock(t.rawFd, true)
	platform.LogOK(fmt.Sprintf("raw proto=%d ready", bipProto))
	wire.LogWireSpoof(t.cfg, t.wire)

	platform.AddMSS(c, dev)
	t.done = make(chan struct{})

	rawFd := t.rawFd
	go t.rxLoop(rawFd, t.tun.Fd0())
	go t.txPollLoop(rawFd)

	platform.Done(dev, addr, peer,
		fmt.Sprintf("proto : IPv4 proto %d  poller×1", bipProto),
		"test  : ping -c3 "+peer,
	)
	return nil
}

func (t *BipTunnel) rxLoop(rawFd int, tun *os.File) {
	var rb platform.RxMmsgBatch
	rb.Init(platform.PerfBatchSize())
	defer rb.Release()

	peer := t.wire.WirePeer(t.peerIP)
	local := t.localIP
	pollMs := platform.PerfPollMs()
	idleMs := pollMs
	bsz := platform.PerfBatchSize()
	batch := platform.NewTunRxBatch(bsz)

	flush := func() {
		n, err := batch.Flush(tun)
		if n == 0 {
			return
		}
		if err != nil && !t.stop.Stopped() {
			platform.LogWarn("tun write: " + err.Error())
		} else if err == nil {
			platform.StatAdd(platform.StatBIPRxWrite, uint64(n))
		}
	}
	defer flush()

	for {
		got, err := rb.Recv(rawFd)
		if got == 0 {
			if t.stop.Stopped() {
				return
			}
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == nil {
				flush()
				platform.StatInc(platform.StatBIPRxPoll)
				_ = platform.PollFD(rawFd, unix.POLLIN, idleMs)
				idleMs = platform.IdleBackoff(idleMs, pollMs)
				continue
			}
			if err == unix.EINTR {
				continue
			}
			platform.LogWarn("bip rx: " + err.Error())
			continue
		}
		idleMs = pollMs
		for i := 0; i < got; i++ {
			pkt := rb.Data(i)
			sa := rb.From4(i)
			if !wire.AcceptWirePeer(pkt, sa, local, peer, t.wire.Src(), t.wire, bipProto) {
				platform.StatInc(platform.StatBIPRxDrop)
				continue
			}
			inner, ok := wire.ParseWireInner(pkt, t.wire.On)
			if !ok || len(inner) == 0 {
				continue
			}
			if t.cfg.Mode == "server" {
				t.lastSrc.Store(wire.RememberPeerRoute(t.wire, sa.Addr, t.peerIP))
			}
			platform.StatInc(platform.StatBIPRxRecv)
			batch.Add(inner)
		}
		if batch.Len() >= bsz {
			flush()
		}
	}
}

func (t *BipTunnel) txPollLoop(rawFd int) {
	poller := platform.NewTunPoller(t.tun, &t.stop)
	defer poller.Close()

	var batch platform.IcmpTxBatch
	bsz := platform.PerfBatchSize()
	var lastDst [4]byte
	var lastPLen int

	flush := func() {
		if batch.N() == 0 {
			return
		}
		platform.StatAdd(platform.StatBIPTxSend, uint64(batch.N()))
		nerr := platform.MmsgSendBatch(rawFd, &batch)
		if t.wire.On {
			sent := batch.N() - nerr
			if sent < 0 {
				sent = 0
			}
			// WireMon.noteTxBatch(sent, nerr, t.wire.Src(), lastDst, bipProto, lastPLen)
		} else if nerr > 0 {
			wire.NoteWireTxErr(nerr)
		}
		for i := 0; i < batch.N(); i++ {
			platform.PutBuf(batch.Frame(i))
			batch.SetFrame(i, nil)
		}
		batch.Reset()
	}

	poller.Run(
		func() {
			platform.StatInc(platform.StatBIPTxPoll)
			if batch.N() > 0 {
				flush()
			}
		},
		func(pkt []byte, n int) bool {
			platform.StatInc(platform.StatBIPTxRead)
			var routeDst [4]byte
			if t.cfg.Mode == "client" {
				routeDst = t.peerIP
			} else if v := t.lastSrc.Load(); v != nil {
				routeDst = v.([4]byte)
			} else {
				platform.StatInc(platform.StatBIPTxNoDst)
				if t.wire.On {
					// WireMon.noteTxNoDst()
				}
				return true
			}
			frame := platform.GetBuf()
			var out []byte
			if t.wire.On {
				out = wire.BuildWireProto(frame, t.wire.Src(), routeDst, bipProto, pkt[:n])
			} else {
				out = frame[:n]
				copy(out, pkt[:n])
			}
			batch.Add(frame, len(out), routeDst, 0)
			lastDst = routeDst
			lastPLen = n
			_, _ = lastDst, lastPLen
			if batch.N() >= bsz {
				flush()
			}
			return !t.stop.Stopped()
		},
	)
	flush()
}

func (t *BipTunnel) Down() error {
	t.doClean()
	platform.LogOK("bip tunnel torn down")
	return nil
}

func (t *BipTunnel) doClean() {
	platform.RestoreTunnelTuning()
	t.stop.Stop()
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
	platform.ReleaseTunnelLock(t.lockFd)
	t.lockFd = nil
	platform.DelMSS(t.DevName())
	platform.NlDown(t.DevName())
}

func (t *BipTunnel) Status() {
	if l, err := netlink.LinkByName(t.DevName()); err == nil {
		fmt.Printf("  %s: flags=%v\n", l.Attrs().Name, l.Attrs().Flags)
	}
}
