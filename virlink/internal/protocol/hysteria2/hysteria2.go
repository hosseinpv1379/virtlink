// tun_hysteria2.go — Hysteria2 site-to-site via QUIC + UDP forwarding.
//
// Hysteria's built-in TUN is a client-only transparent proxy (no ICMP, no bidirectional
// L3 VPN). Both sides use a real virlink kernel TUN; inner IP frames ride UDP on
// 127.0.0.1:wrapPort, forwarded through QUIC by the hysteria client's udpForwarding.
package hysteria2

import (
	"virlink/internal/wire"
	"virlink/internal/platform"
	"virlink/internal/core"
	"virlink/internal/config"
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const hysteria2Subnet = "10.20.52.0/30"

type Hysteria2Tunnel struct {
	cfg           *config.Config
	cmd           *exec.Cmd
	tun           *platform.TunDev
	udpConn       *net.UDPConn
	wrapAddr      *net.UDPAddr // client: hysteria udpForwarding listen target
	lockFd        *os.File
	pidPath       string
	savedRpFilter []platform.SavedSysctl
	stop          platform.StoppedFlag
	lastPeer      atomic.Value // *net.UDPAddr — server wrap return path
}

func (t *Hysteria2Tunnel) DevName() string {
	if t.cfg.Hysteria2.Dev != "" {
		return t.cfg.Hysteria2.Dev
	}
	return platform.TunnelDevName(t.cfg, "hy2-tun0")
}

func (t *Hysteria2Tunnel) OverlayIP() string { return core.OverlayAddr(t.cfg, hysteria2Subnet) }
func (t *Hysteria2Tunnel) PeerIP() string    { return core.PeerAddr(t.cfg, hysteria2Subnet) }

func hysteria2WrapPort(c *config.Config) int {
	port := c.Transport.Port
	if port == 0 {
		port = 443
	}
	return 10000 + port
}

func (t *Hysteria2Tunnel) Up() error {
	c := t.cfg
	hy := c.Hysteria2
	if hy.Config == "" {
		return fmt.Errorf("[hysteria2] config path is required")
	}
	if _, err := os.Stat(hy.Config); err != nil {
		return fmt.Errorf("[hysteria2] config %q: %w", hy.Config, err)
	}
	if _, err := exec.LookPath("hysteria"); err != nil {
		return fmt.Errorf("hysteria not found — platform.Run: virlink-setup → install hysteria2")
	}

	dev := t.DevName()
	addr := t.OverlayIP()
	peer := t.PeerIP()
	port := c.Transport.Port
	if port == 0 {
		port = 443
	}
	wrapPort := hysteria2WrapPort(c)
	mtu := c.Tunnel.MTU
	if mtu == 0 {
		mtu = 1400
	}

	platform.Header("hysteria2 / " + c.Mode)
	platform.ApplyPerfFromConfig(c)
	platform.Step("cleanup...")
	t.doClean()
	t.stop.Reset()

	var err error
	t.lockFd, err = platform.AcquireTunnelLock(dev)
	if err != nil {
		return err
	}

	platform.Step(fmt.Sprintf("TUN device %s ×%d queues...", dev, platform.PerfTunQueues()))
	t.tun, err = platform.OpenTunMulti(dev, platform.PerfTunQueues())
	if err != nil {
		return fmt.Errorf("tun: %w", err)
	}
	l, err := netlink.LinkByName(dev)
	if err != nil {
		return fmt.Errorf("link %s: %w", dev, err)
	}
	if err := netlink.LinkSetMTU(l, mtu); err != nil {
		return fmt.Errorf("mtu: %w", err)
	}
	a, err := netlink.ParseAddr(addr)
	if err != nil {
		return fmt.Errorf("parse overlay %s: %w", addr, err)
	}
	if err := netlink.AddrAdd(l, a); err != nil {
		return fmt.Errorf("addr: %w", err)
	}
	if err := netlink.LinkSetUp(l); err != nil {
		return fmt.Errorf("link up %s: %w", dev, err)
	}
	platform.LogOK(fmt.Sprintf("%s  %s  MTU=%d  queues=%d", dev, addr, mtu, t.tun.QueueCount()))

	if c.Mode == "server" {
		platform.Step(fmt.Sprintf("UDP wrap listener 127.0.0.1:%d...", wrapPort))
		t.udpConn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: wrapPort})
		if err != nil {
			return fmt.Errorf("udp wrap :%d: %w", wrapPort, err)
		}
		platform.TuneUDPConn(t.udpConn)
		platform.LogOK(fmt.Sprintf("UDP wrap 127.0.0.1:%d", wrapPort))
	}

	subcmd := "client"
	if c.Mode == "server" {
		subcmd = "server"
	}
	platform.Step(fmt.Sprintf("starting hysteria %s...", subcmd))
	logPath := hysteria2LogPath(c)
	t.pidPath = hysteria2PIDPath(c)
	_ = os.MkdirAll(filepath.Dir(logPath), 0o755)
	_ = os.MkdirAll(filepath.Dir(t.pidPath), 0o755)

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("hysteria2 log: %w", err)
	}

	t.cmd = exec.Command("hysteria", subcmd, "-c", filepath.Base(hy.Config))
	t.cmd.Dir = filepath.Dir(hy.Config)
	t.cmd.Stdout = logFile
	t.cmd.Stderr = logFile
	if err := t.cmd.Start(); err != nil {
		logFile.Close()
		return fmt.Errorf("hysteria2 start: %w", err)
	}
	go func() { _ = logFile.Close() }()

	platform.Step("waiting for hysteria...")
	if err := waitForHysteria2(logPath, t.cmd, c.Mode, 120*time.Second); err != nil {
		t.stopProcess()
		return err
	}

	if c.Mode == "client" {
		// hysteria client binds udpForwarding on 127.0.0.1:wrapPort — we send there from an ephemeral port.
		platform.Step(fmt.Sprintf("UDP wrap socket → hysteria 127.0.0.1:%d...", wrapPort))
		t.udpConn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			return fmt.Errorf("udp wrap socket: %w", err)
		}
		platform.TuneUDPConn(t.udpConn)
		t.wrapAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: wrapPort}
		platform.LogOK(fmt.Sprintf("UDP wrap → 127.0.0.1:%d", wrapPort))
		platform.Step("keepalive...")
		if _, err := t.udpConn.WriteToUDP([]byte{0}, t.wrapAddr); err != nil {
			platform.LogWarn("wrap keepalive: " + err.Error())
		}
	}

	tun0 := t.tun.Fd0()
	if c.Mode == "server" {
		go t.rxLoopServer(t.udpConn, tun0)
		go t.txPollLoopServer(t.udpConn)
	} else {
		go t.rxLoopClient(t.udpConn, tun0)
		go t.txPollLoopClient(t.udpConn)
	}

	if c.Mode == "client" {
		platform.Step("rp_filter=2 (Hysteria2 TUN)...")
		t.applyHysteria2ClientRpFilter()
	}

	platform.Step(fmt.Sprintf("tuning (%s)...", platform.TuningModeLabel(c)))
	platform.ApplyTunnelTuning(c, dev)
	platform.AddMSS(c, dev)

	platform.LogOK(fmt.Sprintf("hysteria2 running  pid=%d  dev=%s", t.cmd.Process.Pid, dev))
	platform.LogOK(fmt.Sprintf("overlay %s  peer %s  wrap :%d", addr, peer, wrapPort))

	platform.Done(dev, addr, peer,
		fmt.Sprintf("transport : Hysteria2 QUIC :%d  wrap UDP :%d", port, wrapPort),
		"config    : "+hy.Config,
		"log       : "+logPath,
		"test      : ping -c3 "+peer,
		"test      : echo test | nc -u -w2 "+peer+" 9999  (peer: nc -ul 9999)",
	)
	return nil
}

// rxLoopServer receives IP packets from hysteria's UDP forwarding port and writes
// them to the TUN device in batches (recvmmsg → tunWritev).
func (t *Hysteria2Tunnel) rxLoopServer(conn *net.UDPConn, tun *os.File) {
	rawFd, err := platform.UdpConnFD(conn)
	if err != nil {
		t.rxLoopServerBlocking(conn, tun)
		return
	}
	_ = unix.SetNonblock(rawFd, true)

	var rb platform.RxMmsgBatch
	rb.Init(platform.PerfBatchSize())
	defer rb.Release()

	bsz := platform.PerfBatchSize()
	batch := platform.NewTunRxBatch(bsz)
	pollMs := platform.PerfPollMs()

	flush := func() {
		n, ferr := batch.Flush(tun)
		if n > 0 && ferr == nil {
			platform.StatAdd(platform.StatUDPRxWrite, uint64(n))
		}
	}
	defer flush()

	for !t.stop.Stopped() {
		got, rerr := rb.Recv(rawFd)
		if got == 0 {
			if t.stop.Stopped() {
				return
			}
			if rerr == unix.EAGAIN || rerr == unix.EWOULDBLOCK || rerr == nil {
				flush()
				_ = platform.PollFD(rawFd, unix.POLLIN, pollMs)
				continue
			}
			continue
		}
		for i := 0; i < got; i++ {
			pkt := rb.Data(i)
			// Update last peer from the recvmmsg source address.
			sa := rb.From4(i)
			portBE := sa.Port
			t.lastPeer.Store(&net.UDPAddr{
				IP:   net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3]),
				Port: int(portBE>>8 | (portBE&0xff)<<8),
			})
			platform.StatInc(platform.StatUDPRxRecv)
			batch.Add(pkt)
		}
		if batch.Len() >= bsz {
			flush()
		}
	}
}

// rxLoopServerBlocking is the single-packet fallback when recvmmsg is unavailable.
func (t *Hysteria2Tunnel) rxLoopServerBlocking(conn *net.UDPConn, tun *os.File) {
	buf := platform.GetBuf()
	defer platform.PutBuf(buf)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if t.stop.Stopped() {
				return
			}
			continue
		}
		t.lastPeer.Store(src)
		platform.StatInc(platform.StatUDPRxRecv)
		if err := platform.TunWrite(tun, buf[:n]); err != nil && !t.stop.Stopped() {
			platform.LogWarn("tun write: " + err.Error())
		} else {
			platform.StatInc(platform.StatUDPRxWrite)
		}
	}
}

// txPollLoopServer drains the TUN device and sends IP packets to the hysteria
// wrap client via sendmmsg.
func (t *Hysteria2Tunnel) txPollLoopServer(conn *net.UDPConn) {
	rawFd, err := platform.UdpConnFD(conn)
	if err != nil {
		t.txPollLoopServerUnbatched(conn)
		return
	}

	poller := platform.NewTunPollerH(t.tun, &t.stop, 0)
	defer poller.Close()

	var batch platform.IcmpTxBatch
	bsz := platform.PerfBatchSize()

	flush := func() {
		if batch.N() == 0 {
			return
		}
		platform.StatAdd(platform.StatUDPTxSend, uint64(batch.N()))
		if nerr := platform.MmsgSendBatch(rawFd, &batch); nerr > 0 {
			wire.NoteWireTxErr(nerr)
		}
		for i := 0; i < batch.N(); i++ {
			platform.PutBuf(batch.Frame(i))
			batch.SetFrame(i, nil)
		}
		batch.Reset()
	}

	poller.RunOwned(
		func() {
			platform.StatInc(platform.StatUDPTxPoll)
			if batch.N() > 0 {
				flush()
			}
		},
		func(buf []byte, n int) bool {
			platform.StatInc(platform.StatUDPTxRead)
			p, ok := t.lastPeer.Load().(*net.UDPAddr)
			if !ok || p == nil {
				platform.StatInc(platform.StatUDPTxNoDst)
				platform.PutBuf(buf)
				return true
			}
			var dst [4]byte
			copy(dst[:], p.IP.To4())
			port := uint16(p.Port)
			batch.Add(buf, n, dst, port)
			if batch.N() >= bsz {
				flush()
			}
			return !t.stop.Stopped()
		},
	)
	flush()
}

// txPollLoopServerUnbatched is the single-packet fallback for txPollLoopServer.
func (t *Hysteria2Tunnel) txPollLoopServerUnbatched(conn *net.UDPConn) {
	poller := platform.NewTunPoller(t.tun, &t.stop)
	defer poller.Close()

	poller.Run(
		func() { platform.StatInc(platform.StatUDPTxPoll) },
		func(pkt []byte, n int) bool {
			platform.StatInc(platform.StatUDPTxRead)
			p, ok := t.lastPeer.Load().(*net.UDPAddr)
			if !ok || p == nil {
				platform.StatInc(platform.StatUDPTxNoDst)
				return true
			}
			if _, err := conn.WriteToUDP(pkt[:n], p); err != nil && !t.stop.Stopped() {
				platform.LogDebug("udp wrap tx: " + err.Error())
			} else if err == nil {
				platform.StatInc(platform.StatUDPTxSend)
			}
			return !t.stop.Stopped()
		},
	)
}

// rxLoopClient receives IP packets forwarded back by hysteria (client side) and
// writes them to TUN in batches.
func (t *Hysteria2Tunnel) rxLoopClient(conn *net.UDPConn, tun *os.File) {
	rawFd, err := platform.UdpConnFD(conn)
	if err != nil {
		t.rxLoopClientBlocking(conn, tun)
		return
	}
	_ = unix.SetNonblock(rawFd, true)

	var rb platform.RxMmsgBatch
	rb.Init(platform.PerfBatchSize())
	defer rb.Release()

	bsz := platform.PerfBatchSize()
	batch := platform.NewTunRxBatch(bsz)
	pollMs := platform.PerfPollMs()

	flush := func() {
		n, ferr := batch.Flush(tun)
		if n > 0 && ferr == nil {
			platform.StatAdd(platform.StatUDPRxWrite, uint64(n))
		}
	}
	defer flush()

	for !t.stop.Stopped() {
		got, rerr := rb.Recv(rawFd)
		if got == 0 {
			if t.stop.Stopped() {
				return
			}
			if rerr == unix.EAGAIN || rerr == unix.EWOULDBLOCK || rerr == nil {
				flush()
				_ = platform.PollFD(rawFd, unix.POLLIN, pollMs)
				continue
			}
			continue
		}
		platform.StatAdd(platform.StatUDPRxRecv, uint64(got))
		for i := 0; i < got; i++ {
			batch.Add(rb.Data(i))
		}
		if batch.Len() >= bsz {
			flush()
		}
	}
}

// rxLoopClientBlocking is the single-packet fallback for rxLoopClient.
func (t *Hysteria2Tunnel) rxLoopClientBlocking(conn *net.UDPConn, tun *os.File) {
	buf := platform.GetBuf()
	defer platform.PutBuf(buf)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if t.stop.Stopped() {
				return
			}
			continue
		}
		platform.StatInc(platform.StatUDPRxRecv)
		if err := platform.TunWrite(tun, buf[:n]); err != nil && !t.stop.Stopped() {
			platform.LogWarn("tun write: " + err.Error())
		} else {
			platform.StatInc(platform.StatUDPRxWrite)
		}
	}
}

// txPollLoopClient drains the TUN device and sends IP packets toward the hysteria
// udpForwarding port via sendmmsg.
func (t *Hysteria2Tunnel) txPollLoopClient(conn *net.UDPConn) {
	rawFd, err := platform.UdpConnFD(conn)
	if err != nil {
		t.txPollLoopClientUnbatched(conn)
		return
	}

	dst := t.wrapAddr
	if dst == nil {
		return
	}
	var dstArr [4]byte
	copy(dstArr[:], dst.IP.To4())
	dstPort := uint16(dst.Port)

	poller := platform.NewTunPollerH(t.tun, &t.stop, 0)
	defer poller.Close()

	var batch platform.IcmpTxBatch
	bsz := platform.PerfBatchSize()

	flush := func() {
		if batch.N() == 0 {
			return
		}
		platform.StatAdd(platform.StatUDPTxSend, uint64(batch.N()))
		if nerr := platform.MmsgSendBatch(rawFd, &batch); nerr > 0 {
			wire.NoteWireTxErr(nerr)
		}
		for i := 0; i < batch.N(); i++ {
			platform.PutBuf(batch.Frame(i))
			batch.SetFrame(i, nil)
		}
		batch.Reset()
	}

	poller.RunOwned(
		func() {
			platform.StatInc(platform.StatUDPTxPoll)
			if batch.N() > 0 {
				flush()
			}
		},
		func(buf []byte, n int) bool {
			platform.StatInc(platform.StatUDPTxRead)
			batch.Add(buf, n, dstArr, dstPort)
			if batch.N() >= bsz {
				flush()
			}
			return !t.stop.Stopped()
		},
	)
	flush()
}

// txPollLoopClientUnbatched is the single-packet fallback for txPollLoopClient.
func (t *Hysteria2Tunnel) txPollLoopClientUnbatched(conn *net.UDPConn) {
	poller := platform.NewTunPoller(t.tun, &t.stop)
	defer poller.Close()
	dst := t.wrapAddr

	poller.Run(
		func() { platform.StatInc(platform.StatUDPTxPoll) },
		func(pkt []byte, n int) bool {
			platform.StatInc(platform.StatUDPTxRead)
			if dst == nil {
				platform.StatInc(platform.StatUDPTxNoDst)
				return true
			}
			if _, err := conn.WriteToUDP(pkt[:n], dst); err != nil && !t.stop.Stopped() {
				platform.LogDebug("udp wrap tx: " + err.Error())
			} else if err == nil {
				platform.StatInc(platform.StatUDPTxSend)
			}
			return !t.stop.Stopped()
		},
	)
}

func (t *Hysteria2Tunnel) Down() error {
	t.doClean()
	platform.LogOK("hysteria2 tunnel torn down")
	return nil
}

func (t *Hysteria2Tunnel) applyHysteria2ClientRpFilter() {
	for _, k := range []string{"net.ipv4.conf.default.rp_filter", "net.ipv4.conf.all.rp_filter"} {
		prev, err := platform.ReadSysctl(k)
		entry := platform.SavedSysctl{Key: k, Ok: err == nil}
		if entry.Ok {
			entry.Val = prev
		}
		t.savedRpFilter = append(t.savedRpFilter, entry)
		if err := platform.NlSysctl(k, "2"); err != nil {
			platform.LogWarn(fmt.Sprintf("rp_filter %s: %v", k, err))
		}
	}
}

func (t *Hysteria2Tunnel) restoreHysteria2ClientRpFilter() {
	for i := len(t.savedRpFilter) - 1; i >= 0; i-- {
		s := t.savedRpFilter[i]
		if s.Ok {
			_ = platform.NlSysctl(s.Key, s.Val)
		}
	}
	t.savedRpFilter = nil
}

func (t *Hysteria2Tunnel) doClean() {
	t.stop.Stop()
	t.stopProcess()
	t.restoreHysteria2ClientRpFilter()
	if t.udpConn != nil {
		t.udpConn.Close()
		t.udpConn = nil
	}
	t.wrapAddr = nil
	if t.tun != nil {
		t.tun.Close()
		t.tun = nil
	}
	if t.lockFd != nil {
		platform.ReleaseTunnelLock(t.lockFd)
		t.lockFd = nil
	}
	platform.RestoreTunnelTuning()
	platform.DelMSS(t.DevName())
	platform.NlDown(t.DevName())
	if t.pidPath != "" {
		_ = os.Remove(t.pidPath)
		t.pidPath = ""
	}
}

func (t *Hysteria2Tunnel) stopProcess() {
	if t.cmd != nil && t.cmd.Process != nil {
		_ = t.cmd.Process.Signal(os.Interrupt)
		doneCh := make(chan struct{})
		go func() {
			_ = t.cmd.Wait()
			close(doneCh)
		}()
		select {
		case <-doneCh:
		case <-time.After(5 * time.Second):
			_ = t.cmd.Process.Kill()
		}
		t.cmd = nil
	}
}

func (t *Hysteria2Tunnel) Status() {
	dev := t.DevName()
	if l, err := netlink.LinkByName(dev); err == nil {
		fmt.Printf("  %s: flags=%v\n", l.Attrs().Name, l.Attrs().Flags)
	}
	if t.cmd != nil && t.cmd.Process != nil {
		fmt.Printf("  hysteria pid: %d\n", t.cmd.Process.Pid)
	}
	fmt.Printf("  config: %s\n", t.cfg.Hysteria2.Config)
	fmt.Printf("  wrap port: %d\n", hysteria2WrapPort(t.cfg))
}

func waitForHysteria2(logPath string, cmd *exec.Cmd, mode string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cmd != nil && !hysteria2ProcessAlive(cmd) {
			return fmt.Errorf("hysteria exited before ready:\n%s",
				hysteria2LogTail(logPath, 30))
		}
		if logPath != "" && hysteria2LogFailed(logPath) {
			return fmt.Errorf("hysteria failed (see %s):\n%s", logPath, hysteria2LogTail(logPath, 30))
		}
		if mode == "server" {
			if logPath != "" && hysteria2LogContains(logPath, "server up and running") {
				return nil
			}
		} else if logPath != "" && hysteria2LogContains(logPath, "connected to server") {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	hint := "check " + logPath + " — server running? UDP port open? auth/TLS/obfs match?"
	if logPath != "" {
		return fmt.Errorf("timeout waiting for hysteria (%s):\n%s",
			hint, hysteria2LogTail(logPath, 30))
	}
	return fmt.Errorf("timeout waiting for hysteria")
}

func hysteria2LogFailed(path string) bool {
	tail := hysteria2LogTail(path, 40)
	if tail == "" || strings.HasPrefix(tail, "(log") {
		return false
	}
	s := strings.ToLower(tail)
	for _, needle := range []string{
		"fatal", "authentication failed", "failed to authenticate",
		"certificate verify failed", "failed to run tun", "no such file",
		"failed to load", "failed to parse", "failed to listen",
	} {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

func hysteria2ProcessAlive(cmd *exec.Cmd) bool {
	if cmd == nil || cmd.Process == nil {
		return false
	}
	return cmd.Process.Signal(syscall.Signal(0)) == nil
}

func hysteria2LogContains(path, needle string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return bytes.Contains(b, []byte(needle))
}

func hysteria2LogTail(path string, n int) string {
	if path == "" {
		return "(no log path)"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("(log unreadable: %v)", err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) == 0 {
		return "(log empty — hysteria failed immediately?)"
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func hysteria2LogPath(c *config.Config) string {
	name := tunnelInstanceName(c)
	return filepath.Join("/var/log/virlink", name+"-hysteria2.log")
}

func hysteria2PIDPath(c *config.Config) string {
	name := tunnelInstanceName(c)
	return filepath.Join("/var/run/virlink", name+"-hysteria2.pid")
}

func tunnelInstanceName(c *config.Config) string {
	if c.Tunnel.Name != "" {
		return c.Tunnel.Name
	}
	return c.Tunnel.Type + "-" + c.Tunnel.Mode
}
