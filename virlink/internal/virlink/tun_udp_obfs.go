// tun_udp_obfs.go — obfuscated UDP tunnel.
//
// Architecture:
//   [app] → [TUN device] → [AES-256-GCM encrypt] → [fake header] → [UDP socket]
//              ↑                                                          ↓
//   [app] ← [TUN device] ← [AES-256-GCM decrypt] ← [strip header] ← [UDP socket]
//
// The tunnel creates a real kernel TUN interface (via /dev/net/tun).
// Packets are encrypted inside the binary before going out — the kernel
// never sees plaintext on the wire.
//
// Mask modes (bypass Iranian DPI):
//   noise  — pure ciphertext, no header; looks like random noise
//   quic   — fake QUIC v1 Long Header prefix; looks like QUIC (port 443 best)
//   dtls   — fake DTLS 1.2 Record header; looks like encrypted DTLS
//
// Wire frame format:
//   [mask header (0/15/13 bytes)] [12-byte AES nonce] [AES-256-GCM ciphertext]
//   Inside ciphertext: [flags(1B)] [original IP packet] [opt: padding] [opt: pad_len(1B)]
package virlink

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync/atomic"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const obfsSubnet = "10.20.20.0/24"

// fake QUIC v1 Initial Long Header (15 bytes, DCID randomised per packet)
var quicPrefix = [15]byte{
	0xC0,                                           // Long Header + Initial type
	0x00, 0x00, 0x00, 0x01,                         // QUIC version 1
	0x08,                                           // DCID length = 8
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // DCID placeholder
	0x00, // SCID length = 0
}

// fake DTLS 1.2 Record Header (13 bytes, length filled per packet)
var dtlsPrefix = [13]byte{
	0x16,             // ContentType: Handshake
	0xfe, 0xfd,       // Version: DTLS 1.2
	0x00, 0x00,       // Epoch
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Sequence
	0x00, 0x00,       // Length placeholder
}

// UdpObfsTunnel is an obfuscated userspace tunnel.
// It is the only tunnel type that does NOT use kernel GRE/IPIP/etc.
// All crypto and forwarding happens inside this Go process.
//
// Performance: the cipher.AEAD is created ONCE in Up() and reused for every
// packet.  cipher.AEAD.Seal/Open are documented as safe for concurrent use,
// so both goroutines share the same object.
type UdpObfsTunnel struct {
	cfg      *Config
	tun      *TunDev
	udpConn  *net.UDPConn
	gcm      cipher.AEAD
	done     chan struct{}
	stop     stoppedFlag
	lastPeer atomic.Value
}

func (t *UdpObfsTunnel) DevName() string   { return tunnelDevName(t.cfg, "udpobfs0") }
func (t *UdpObfsTunnel) OverlayIP() string { return overlayAddr(t.cfg, obfsSubnet) }
func (t *UdpObfsTunnel) PeerIP() string    { return peerAddr(t.cfg, obfsSubnet) }

func (t *UdpObfsTunnel) Up() error {
	c := t.cfg
	dev := t.DevName()
	addr := t.OverlayIP()
	peer := t.PeerIP()
	port := c.Transport.Port
	mtu := c.Tunnel.MTU
	if mtu == 0 {
		mtu = 1400
	}

	mask := c.Obfs.Mask
	if mask == "" {
		mask = "noise"
	}

	if c.Obfs.Key == "" {
		return fmt.Errorf("[obfs] key must be set (shared secret between client and server)")
	}
	key := deriveObfsKey(c.Obfs.Key)

	// ── cache cipher once — reused for every packet ───────────────────────────
	// aes.NewCipher + cipher.NewGCM are expensive; doing this per-packet would
	// be the dominant CPU cost at high packet rates.
	var err error
	{
		block, berr := aes.NewCipher(key[:])
		if berr != nil {
			return fmt.Errorf("aes init: %w", berr)
		}
		t.gcm, err = cipher.NewGCM(block)
		if err != nil {
			return fmt.Errorf("gcm init: %w", err)
		}
	}

	header(fmt.Sprintf("udp-obfs / %s  mask=%s", c.Mode, mask))
	applyPerfFromConfig(c)

	step("cleanup...")
	t.doClean()
	t.stop.reset()

	// ── TUN device (/dev/net/tun) ─────────────────────────────────────────────
	step(fmt.Sprintf("TUN device %s ×%d queues...", dev, perfTunQueues()))
	t.tun, err = openTunMulti(dev, perfTunQueues())
	if err != nil {
		return fmt.Errorf("tun: %w", err)
	}

	// Configure via netlink (native)
	l, err := netlink.LinkByName(dev)
	if err != nil {
		return fmt.Errorf("link %s: %w", dev, err)
	}
	if err := netlink.LinkSetMTU(l, mtu); err != nil {
		return fmt.Errorf("set mtu: %w", err)
	}
	a, _ := netlink.ParseAddr(addr)
	if err := netlink.AddrAdd(l, a); err != nil {
		return fmt.Errorf("addr add: %w", err)
	}
	if err := netlink.LinkSetUp(l); err != nil {
		return fmt.Errorf("link up: %w", err)
	}
	logOK(fmt.Sprintf("%s  %s  MTU=%d  queues=%d", dev, addr, mtu, t.tun.QueueCount()))

	step(fmt.Sprintf("tuning (%s)...", tuningModeLabel(c)))
	applyTunnelTuning(c, dev)

	// ── UDP socket ────────────────────────────────────────────────────────────
	step(fmt.Sprintf("UDP socket :%d...", port))
	t.udpConn, err = net.ListenUDP("udp4", &net.UDPAddr{Port: port})
	if err != nil {
		return fmt.Errorf("udp listen :%d: %w", port, err)
	}
	tuneUDPConn(t.udpConn) // 4 MB socket buffers — prevents drops under burst
	logOK(fmt.Sprintf("UDP :%d", port))

	t.done = make(chan struct{})

	// client knows where to send; server learns from first incoming packet
	var fixedPeer *net.UDPAddr
	if c.Mode == "client" {
		fixedPeer = &net.UDPAddr{IP: net.ParseIP(c.RemoteIP), Port: port}
		t.lastPeer.Store(fixedPeer)
	}

	// ── goroutines ────────────────────────────────────────────────────────────
	// Capture local references NOW. doClean() will nil out t.udpConn / t.tunFd
	// to signal cleanup, but goroutines hold their own ref so they never
	// dereference a nil pointer — they simply get an error and check t.done.
	gcm := t.gcm
	go t.rxLoop(t.udpConn, t.tun.WriteFd(), gcm, mask)
	go t.txPollLoop(t.udpConn, gcm, mask, fixedPeer)

	logOK(fmt.Sprintf("encrypt=AES-256-GCM  mask=%s  padding=%v", mask, c.Obfs.Padding))

	done(dev, addr, peer,
		fmt.Sprintf("mask     : %s", mask),
		fmt.Sprintf("port     : %d  (UDP)", port),
		fmt.Sprintf("padding  : %v", c.Obfs.Padding),
		"test     : ping -c3 "+peer,
	)
	return nil
}

// rxLoop: UDP → decrypt → TUN (recvmmsg + tunWritev batching).
func (t *UdpObfsTunnel) rxLoop(conn *net.UDPConn, tun *os.File, gcm cipher.AEAD, mask string) {
	rawFd, err := udpConnFD(conn)
	if err != nil {
		t.rxLoopBlocking(conn, tun, gcm, mask)
		return
	}
	_ = unix.SetNonblock(rawFd, true)

	var rb rxMmsgBatch
	rb.init(perfBatchSize())
	defer rb.release()

	bsz := perfBatchSize()
	pollMs := perfPollMs()
	idleMs := pollMs
	batch := newTunRxBatch(bsz)
	var lastPeerAddr [4]byte
	var lastPeerPort uint16

	flush := func() {
		written, total, err := batch.flush(tun)
		reportTunRxFlush(written, total, err, statUDPRxWrite, statUDPRxDropWrite, "udp-obfs:tun_write", "UDP-OBFS", &t.stop)
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
				_ = pollFD(rawFd, unix.POLLIN, idleMs)
				idleMs = idleBackoff(idleMs, pollMs)
				continue
			}
			if err == unix.EINTR {
				continue
			}
			continue
		}
		idleMs = pollMs
		for i := 0; i < got; i++ {
			pkt := rb.data(i)
			sa := rb.from4(i)
			plain, derr := obfsDecrypt(pkt, gcm, mask, t.cfg.Obfs.Padding)
			if derr != nil {
				logDebug(fmt.Sprintf("rx from %v: %v", sa, derr))
				continue
			}
			saPort := uint16(sa.Port>>8) | uint16(sa.Port<<8)
			if sa.Addr != lastPeerAddr || saPort != lastPeerPort {
				lastPeerAddr = sa.Addr
				lastPeerPort = saPort
				t.lastPeer.Store(&net.UDPAddr{
					IP:   net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3]),
					Port: int(saPort),
				})
			}
			batch.add(plain)
		}
		if batch.len() >= bsz {
			flush()
		}
	}
}

func (t *UdpObfsTunnel) rxLoopBlocking(conn *net.UDPConn, tun *os.File, gcm cipher.AEAD, mask string) {
	buf := getBuf()
	defer putBuf(buf)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if t.stop.stopped() {
				return
			}
			continue
		}
		pkt, err := obfsDecrypt(buf[:n], gcm, mask, t.cfg.Obfs.Padding)
		if err != nil {
			logDebug(fmt.Sprintf("rx from %s: %v", src, err))
			continue
		}
		t.lastPeer.Store(src)
		if err := tunWrite(tun, pkt); err != nil && !t.stop.stopped() {
			logWarn("tun write: " + err.Error())
		}
	}
}

func (t *UdpObfsTunnel) txPollLoop(conn *net.UDPConn, gcm cipher.AEAD, mask string, fixed *net.UDPAddr) {
	rawFd, err := udpConnFD(conn)
	if err != nil {
		t.txPollLoopUnbatched(conn, gcm, mask, fixed)
		return
	}

	poller := newTunPoller(t.tun, &t.stop)
	defer poller.close()

	var batch icmpTxBatch
	bsz := perfBatchSize()
	var curDst [4]byte
	var curPort uint16
	var haveDst bool

	flush := func() {
		if batch.n == 0 {
			return
		}
		if nerr := mmsgSendBatch(rawFd, &batch); nerr > 0 {
			logDebug(fmt.Sprintf("obfs tx batch: %d failed", nerr))
		}
		for i := 0; i < batch.n; i++ {
			putBuf(batch.frames[i])
			batch.frames[i] = nil
		}
		batch.reset()
		haveDst = false
	}

	addPkt := func(dst [4]byte, port uint16, payload []byte) {
		if haveDst && (dst != curDst || port != curPort) {
			flush()
		}
		curDst = dst
		curPort = port
		haveDst = true
		frameBuf := getBuf()
		frame, encErr := obfsEncrypt(frameBuf, payload, gcm, mask, t.cfg.Obfs.Padding)
		if encErr != nil {
			putBuf(frameBuf)
			return
		}
		batch.add(frameBuf, len(frame), dst, port)
		if batch.n >= bsz {
			flush()
		}
	}

	poller.Run(
		func() {
			if batch.n > 0 {
				flush()
			}
		},
		func(pkt []byte, n int) bool {
			var dst [4]byte
			var port uint16
			if fixed != nil {
				copy(dst[:], fixed.IP.To4())
				port = uint16(fixed.Port)
			} else if p, ok := t.lastPeer.Load().(*net.UDPAddr); ok && p != nil {
				copy(dst[:], p.IP.To4())
				port = uint16(p.Port)
			} else {
				return true
			}
			addPkt(dst, port, pkt[:n])
			return !t.stop.stopped()
		},
	)
	flush()
}

func (t *UdpObfsTunnel) txPollLoopUnbatched(conn *net.UDPConn, gcm cipher.AEAD, mask string, fixed *net.UDPAddr) {
	poller := newTunPoller(t.tun, &t.stop)
	defer poller.close()

	poller.Run(nil, func(pkt []byte, n int) bool {
		frameBuf := getBuf()
		frame, err := obfsEncrypt(frameBuf, pkt[:n], gcm, mask, t.cfg.Obfs.Padding)
		if err != nil {
			putBuf(frameBuf)
			return true
		}
		dst := fixed
		if dst == nil {
			if p, ok := t.lastPeer.Load().(*net.UDPAddr); ok && p != nil {
				dst = p
			} else {
				putBuf(frameBuf)
				return true
			}
		}
		if _, err := conn.WriteToUDP(frame, dst); err != nil && !t.stop.stopped() {
			logDebug("obfs tx: " + err.Error())
		}
		putBuf(frameBuf)
		return !t.stop.stopped()
	})
}

func (t *UdpObfsTunnel) Down() error {
	t.doClean()
	logOK("udp-obfs torn down")
	return nil
}

func (t *UdpObfsTunnel) doClean() {
	restoreTunnelTuning()
	t.stop.stop()
	if t.done != nil {
		close(t.done)
		t.done = nil
	}
	if t.udpConn != nil {
		t.udpConn.Close()
		t.udpConn = nil
	}
	if t.tun != nil {
		t.tun.Close()
		t.tun = nil
	}
	nlDown(t.DevName())
}

func (t *UdpObfsTunnel) Status() {
	if l, err := netlink.LinkByName(t.DevName()); err == nil {
		fmt.Printf("  %s: flags=%v\n", l.Attrs().Name, l.Attrs().Flags)
	}
}

// ── crypto ────────────────────────────────────────────────────────────────────

// deriveObfsKey turns an arbitrary passphrase into a 32-byte AES-256 key.
func deriveObfsKey(passphrase string) [32]byte {
	return sha256.Sum256([]byte(passphrase))
}

// obfsEncrypt encrypts pkt and prepends the chosen mask header, writing
// everything into frame (a pktPool buffer) in place — zero heap allocation.
// gcm is the cached cipher — created once in Up(), safe for concurrent use.
//
// Plaintext inside GCM:
//
//	[flags(1B)] [original packet] [random pad (optional)] [padLen(1B)]
//	flags: 0x01 = padding present
func obfsEncrypt(frame, pkt []byte, gcm cipher.AEAD, mask string, padding bool) ([]byte, error) {
	var hdrLen int
	switch mask {
	case "quic":
		hdrLen = len(quicPrefix)
	case "dtls":
		hdrLen = len(dtlsPrefix)
	}

	nonceOff := hdrLen
	plainOff := nonceOff + 12
	nonce := frame[nonceOff:plainOff]
	innerLen := 1 + len(pkt)
	padLen := 0
	if padding {
		// Read nonce (12B) + one extra byte for pad-length selection in a single syscall,
		// saving one getrandom() call compared to rand.Read(nonce) + mustRandByte().
		var noncePad [13]byte
		if _, err := rand.Read(noncePad[:]); err != nil {
			return nil, err
		}
		copy(nonce, noncePad[:12])
		padLen = int(noncePad[12]%48) + 4
		innerLen += padLen
	} else {
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
	}

	// plaintext, written directly into frame: flags(1B) | packet | [pad...] [padLen(1B)]
	plain := frame[plainOff : plainOff+innerLen]
	if padding {
		plain[0] = 0x01
		copy(plain[1:], pkt)
		padStart := 1 + len(pkt)
		if _, err := rand.Read(plain[padStart : padStart+padLen-1]); err != nil {
			return nil, err
		}
		plain[innerLen-1] = byte(padLen)
	} else {
		plain[0] = 0x00
		copy(plain[1:], pkt)
	}

	// encrypt in place — dst aliases plain exactly (documented crypto/cipher idiom).
	ciphertext := gcm.Seal(plain[:0], nonce, plain, nil)

	// mask header, written last since dtls needs the final payload length.
	switch mask {
	case "quic":
		copy(frame[:hdrLen], quicPrefix[:])
		_, _ = rand.Read(frame[6:14]) // randomise DCID per packet
	case "dtls":
		copy(frame[:hdrLen], dtlsPrefix[:])
		payLen := len(nonce) + len(ciphertext)
		binary.BigEndian.PutUint16(frame[11:13], uint16(payLen))
	}

	return frame[:plainOff+len(ciphertext)], nil
}

// obfsDecrypt reverses obfsEncrypt, decrypting in place into frame's backing
// array (zero heap allocation). The returned slice aliases frame, so callers
// must consume it before frame is reused (rxLoop does so immediately).
func obfsDecrypt(frame []byte, gcm cipher.AEAD, mask string, _ bool) ([]byte, error) {
	switch mask {
	case "quic":
		if len(frame) < len(quicPrefix) {
			return nil, fmt.Errorf("too short for quic header")
		}
		frame = frame[len(quicPrefix):]
	case "dtls":
		if len(frame) < len(dtlsPrefix) {
			return nil, fmt.Errorf("too short for dtls header")
		}
		frame = frame[len(dtlsPrefix):]
	}

	ns := gcm.NonceSize()
	if len(frame) < ns+gcm.Overhead()+1 {
		return nil, fmt.Errorf("frame too short (%d bytes)", len(frame))
	}

	ciphertext := frame[ns:]
	inner, err := gcm.Open(ciphertext[:0], frame[:ns], ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM: %w", err)
	}

	// parse inner: flags(1B) | packet | [pad]
	flags := inner[0]
	data := inner[1:]
	if flags&0x01 != 0 {
		// strip padding: last byte = total pad length
		if len(data) < 1 {
			return nil, fmt.Errorf("padded frame too short")
		}
		padLen := int(data[len(data)-1])
		if padLen < 1 || padLen > len(data) {
			return nil, fmt.Errorf("invalid pad length %d", padLen)
		}
		data = data[:len(data)-padLen]
	}
	return data, nil
}

