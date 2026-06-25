// tun_bip.go — BIP tunnel (IPv4 protocol 58).
//
// Performance (v2.7): multi-queue TUN, peer filter, non-blocking raw socket.
package main

import (
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
	cfg     *Config
	tun     *TunDev
	rawFd   int
	lockFd  *os.File
	done    chan struct{}
	stop    stoppedFlag
	lastSrc atomic.Value
	peerIP  [4]byte
	localIP [4]byte
}

func (t *BipTunnel) DevName() string   { return "bip-tun0" }
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

	header("bip / " + c.Mode)
	applyPerfFromConfig(c)
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

	t.rawFd, err = unix.Socket(unix.AF_INET, unix.SOCK_RAW, bipProto)
	if err != nil {
		return fmt.Errorf("SOCK_RAW proto=%d: %w", bipProto, err)
	}
	_ = unix.SetNonblock(t.rawFd, true)
	tuneRawSock(t.rawFd)
	logOK(fmt.Sprintf("raw proto=%d ready", bipProto))

	addMSS(dev)
	t.done = make(chan struct{})

	rawFd := t.rawFd
	go t.rxLoop(rawFd, t.tun.Fd0())
	for _, q := range t.tun.fds {
		go t.txLoop(rawFd, q)
	}

	done(dev, addr, peer,
		fmt.Sprintf("proto : IPv4 proto %d  queues=%d", bipProto, t.tun.QueueCount()),
		"test  : ping -c3 "+peer,
	)
	return nil
}

func (t *BipTunnel) rxLoop(rawFd int, tun *os.File) {
	buf := getBuf()
	defer putBuf(buf)
	peer, local := t.peerIP, t.localIP
	pollMs := perfPollMs()
	idleMs := pollMs
	for {
		n, from, err := unix.Recvfrom(rawFd, buf, 0)
		if err != nil {
			if t.stop.stopped() {
				return
			}
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				_ = pollFD(rawFd, unix.POLLIN, idleMs)
				if idleMs < 50 {
					idleMs += pollMs
				}
				continue
			}
			if err == unix.EINTR {
				continue
			}
			logWarn("bip rx: " + err.Error())
			continue
		}
		idleMs = pollMs
		sa, ok := from.(*unix.SockaddrInet4)
		if !ok || sa.Addr == local || sa.Addr != peer {
			continue
		}
		if n < 20 {
			continue
		}
		ihl := int(buf[0]&0xf) * 4
		if n <= ihl {
			continue
		}
		if t.cfg.Mode == "server" {
			t.lastSrc.Store(sa.Addr)
		}
		if err := tunWrite(tun, buf[ihl:n]); err != nil && !t.stop.stopped() {
			logWarn("tun write: " + err.Error())
		}
	}
}

func (t *BipTunnel) txLoop(rawFd int, qfd *os.File) {
	_ = unix.SetNonblock(int(qfd.Fd()), true)
	tunFD := int(qfd.Fd())
	buf := getBuf()
	defer putBuf(buf)
	pollMs := perfPollMs()
	idleMs := pollMs
	for !t.stop.stopped() {
		n, err := tunReadNB(qfd, buf)
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			_ = pollFD(tunFD, unix.POLLIN, idleMs)
			if idleMs < 50 {
				idleMs += pollMs
			}
			continue
		}
		if err != nil || n == 0 {
			if err != nil && !t.stop.stopped() {
				logWarn("bip tun read: " + err.Error())
			}
			continue
		}
		idleMs = pollMs
		var dst [4]byte
		if t.cfg.Mode == "client" {
			dst = t.peerIP
		} else if v := t.lastSrc.Load(); v != nil {
			dst = v.([4]byte)
		} else {
			continue
		}
		sa := &unix.SockaddrInet4{Addr: dst}
		if err := unix.Sendto(rawFd, buf[:n], 0, sa); err != nil && err != unix.EAGAIN {
			logDebug("bip tx: " + err.Error())
		}
	}
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
