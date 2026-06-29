// tun_udp_obfs.go — obfuscated UDP tunnel.
//
// Architecture:
//   [app] → [TUN device] → [AES-256-GCM encrypt] → [fake platform.Header] → [UDP socket]
//              ↑                                                          ↓
//   [app] ← [TUN device] ← [AES-256-GCM decrypt] ← [strip platform.Header] ← [UDP socket]
//
// The tunnel creates a real kernel TUN interface (via /dev/net/tun).
// Packets are encrypted inside the binary before going out — the kernel
// never sees plaintext on the wire.
//
// Mask modes (bypass Iranian DPI):
//   noise  — pure ciphertext, no platform.Header; looks like random noise
//   quic   — fake QUIC v1 Long Header prefix; looks like QUIC (port 443 best)
//   dtls   — fake DTLS 1.2 Record platform.Header; looks like encrypted DTLS
//
// Wire frame format:
//   [mask platform.Header (0/15/13 bytes)] [12-byte AES nonce] [AES-256-GCM ciphertext]
//   Inside ciphertext: [flags(1B)] [original IP packet] [opt: padding] [opt: pad_len(1B)]
package udpobfs

import (
	"virlink/internal/platform"
	"virlink/internal/core"
	"virlink/internal/config"
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
	cfg      *config.Config
	tun      *platform.TunDev
	udpConn  *net.UDPConn
	gcm      cipher.AEAD
	done chan struct{}
	stop     platform.StoppedFlag
	lastPeer atomic.Value
}

func (t *UdpObfsTunnel) DevName() string   { return platform.TunnelDevName(t.cfg, "udpobfs0") }
func (t *UdpObfsTunnel) OverlayIP() string { return core.OverlayAddr(t.cfg, obfsSubnet) }
func (t *UdpObfsTunnel) PeerIP() string    { return core.PeerAddr(t.cfg, obfsSubnet) }

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

	platform.Header(fmt.Sprintf("udp-obfs / %s  mask=%s", c.Mode, mask))
	platform.ApplyPerfFromConfig(c)

	platform.Step("cleanup...")
	t.doClean()
	t.stop.Reset()

	// ── TUN device (/dev/net/tun) ─────────────────────────────────────────────
	platform.Step(fmt.Sprintf("TUN device %s ×%d queues...", dev, platform.PerfTunQueues()))
	t.tun, err = platform.OpenTunMulti(dev, platform.PerfTunQueues())
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
	platform.LogOK(fmt.Sprintf("%s  %s  MTU=%d  queues=%d", dev, addr, mtu, t.tun.QueueCount()))

	platform.Step(fmt.Sprintf("tuning (%s)...", platform.TuningModeLabel(c)))
	platform.ApplyTunnelTuning(c, dev)

	// ── UDP socket ────────────────────────────────────────────────────────────
	platform.Step(fmt.Sprintf("UDP socket :%d...", port))
	t.udpConn, err = net.ListenUDP("udp4", &net.UDPAddr{Port: port})
	if err != nil {
		return fmt.Errorf("udp listen :%d: %w", port, err)
	}
	platform.TuneUDPConn(t.udpConn) // 4 MB socket buffers — prevents drops under burst
	platform.LogOK(fmt.Sprintf("UDP :%d", port))

	t.done = make(chan struct{})

	// client knows where to send; server learns from first incoming packet
	var fixedPeer *net.UDPAddr
	if c.Mode == "client" {
		fixedPeer = &net.UDPAddr{IP: net.ParseIP(c.RemoteIP), Port: port}
		t.lastPeer.Store(fixedPeer)
	}

	// ── goroutines ────────────────────────────────────────────────────────────
	// ReadFromUDP RX + batched WriteToUDP TX (recvmmsg/sendmmsg on *net.UDPConn
	// is unreliable on some kernels — same fix as plain UDP tunnel).
	gcm := t.gcm
	go t.rxLoopBlocking(t.udpConn, t.tun.Fd0(), gcm, mask)
	go t.txPollLoop(t.udpConn, gcm, mask, fixedPeer)

	platform.LogOK(fmt.Sprintf("encrypt=AES-256-GCM  mask=%s  padding=%v", mask, c.Obfs.Padding))

	platform.Done(dev, addr, peer,
		fmt.Sprintf("mask     : %s", mask),
		fmt.Sprintf("port     : %d  (UDP)", port),
		fmt.Sprintf("padding  : %v", c.Obfs.Padding),
		"test     : ping -c3 "+peer,
	)
	return nil
}

// rxLoopBlocking: UDP → decrypt → TUN (ReadFromUDP + batched tunWrite).
func (t *UdpObfsTunnel) rxLoopBlocking(conn *net.UDPConn, tun *os.File, gcm cipher.AEAD, mask string) {
	buf := platform.GetBuf()
	defer platform.PutBuf(buf)

	bsz := platform.PerfBatchSize()
	batch := platform.NewTunRxBatch(bsz)

	flush := func() {
		n, err := batch.Flush(tun)
		if n == 0 {
			return
		}
		if err != nil && !t.stop.Stopped() {
			platform.LogWarn("tun write: " + err.Error())
		}
	}
	defer flush()

	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if t.stop.Stopped() {
				return
			}
			continue
		}
		pkt, derr := obfsDecrypt(buf[:n], gcm, mask, t.cfg.Obfs.Padding)
		if derr != nil {
			platform.LogDebug(fmt.Sprintf("rx from %s: %v", src, derr))
			continue
		}
		t.lastPeer.Store(src)
		batch.Add(pkt)
		if batch.Len() >= bsz {
			flush()
		}
	}
}

func (t *UdpObfsTunnel) txPollLoop(conn *net.UDPConn, gcm cipher.AEAD, mask string, fixed *net.UDPAddr) {
	poller := platform.NewTunPoller(t.tun, &t.stop)
	defer poller.Close()

	bsz := platform.PerfBatchSize()
	var curDst *net.UDPAddr
	var frames [][]byte
	var lens []int

	flush := func() {
		if len(frames) == 0 || curDst == nil {
			return
		}
		for i, fb := range frames {
			if _, err := conn.WriteToUDP(fb[:lens[i]], curDst); err != nil && !t.stop.Stopped() {
				platform.LogDebug("obfs tx: " + err.Error())
			}
			platform.PutBuf(fb)
		}
		frames = frames[:0]
		lens = lens[:0]
		curDst = nil
	}

	resolveDst := func() *net.UDPAddr {
		if fixed != nil {
			return fixed
		}
		if p, ok := t.lastPeer.Load().(*net.UDPAddr); ok && p != nil {
			return p
		}
		return nil
	}

	poller.Run(
		func() {
			if len(frames) > 0 {
				flush()
			}
		},
		func(pkt []byte, n int) bool {
			dst := resolveDst()
			if dst == nil {
				return true
			}
			if curDst != nil && (curDst.IP.String() != dst.IP.String() || curDst.Port != dst.Port) {
				flush()
			}
			curDst = dst
			frameBuf := platform.GetBuf()
			frame, encErr := obfsEncrypt(frameBuf, pkt[:n], gcm, mask, t.cfg.Obfs.Padding)
			if encErr != nil {
				platform.PutBuf(frameBuf)
				return true
			}
			frames = append(frames, frameBuf)
			lens = append(lens, len(frame))
			if len(frames) >= bsz {
				flush()
			}
			return !t.stop.Stopped()
		},
	)
	flush()
}

func (t *UdpObfsTunnel) Down() error {
	t.doClean()
	platform.LogOK("udp-obfs torn down")
	return nil
}

func (t *UdpObfsTunnel) doClean() {
	platform.RestoreTunnelTuning()
	t.stop.Stop()
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
	platform.NlDown(t.DevName())
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

// obfsEncrypt encrypts pkt and prepends the chosen mask platform.Header, writing
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

	// mask platform.Header, written last since dtls needs the final payload length.
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
			return nil, fmt.Errorf("too short for quic platform.Header")
		}
		frame = frame[len(quicPrefix):]
	case "dtls":
		if len(frame) < len(dtlsPrefix) {
			return nil, fmt.Errorf("too short for dtls platform.Header")
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

