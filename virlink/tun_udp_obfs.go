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
package main

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
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	obfsSubnet = "10.20.20.0/24"

	// Linux TUN constants
	iffTun   = 0x0001
	iffNoPi  = 0x1000
	tunSetIff = uintptr(0x400454ca) // TUNSETIFF ioctl
)

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
	tunFd    *os.File
	udpConn  *net.UDPConn
	gcm      cipher.AEAD  // cached — avoids aes.NewCipher+NewGCM per packet
	done     chan struct{}
	lastPeer atomic.Value // *net.UDPAddr — server dynamically tracks client
}

func (t *UdpObfsTunnel) DevName() string   { return "udpobfs0" }
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

	step("sysctl (via /proc/sys)...")
	applySysctl()

	step("cleanup...")
	t.doClean()

	// ── TUN device (/dev/net/tun) ─────────────────────────────────────────────
	step(fmt.Sprintf("TUN device %s...", dev))
	t.tunFd, err = openTunDev(dev)
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
	logOK(fmt.Sprintf("%s  %s  MTU=%d", dev, addr, mtu))

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
	gcm := t.gcm // local ref (cipher.AEAD is safe for concurrent use)
	go t.rxLoop(t.udpConn, t.tunFd, gcm, mask, mtu)
	go t.txLoop(t.udpConn, t.tunFd, gcm, mask, mtu, fixedPeer)

	logOK(fmt.Sprintf("encrypt=AES-256-GCM  mask=%s  padding=%v", mask, c.Obfs.Padding))

	done(dev, addr, peer,
		fmt.Sprintf("mask     : %s", mask),
		fmt.Sprintf("port     : %d  (UDP)", port),
		fmt.Sprintf("padding  : %v", c.Obfs.Padding),
		"test     : ping -c3 "+peer,
	)
	return nil
}

// rxLoop: UDP → decrypt → TUN
// conn and tun are passed as values so they're never nil after doClean().
// Uses a pre-allocated buffer from the pool — zero per-packet allocation.
func (t *UdpObfsTunnel) rxLoop(conn *net.UDPConn, tun *os.File, gcm cipher.AEAD, mask string, mtu int) {
	buf := getBuf()
	defer putBuf(buf)
	_ = mtu
	for {
		select {
		case <-t.done:
			return
		default:
		}

		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-t.done:
				return
			default:
				logWarn("rx: " + err.Error())
				continue
			}
		}

		pkt, err := obfsDecrypt(buf[:n], gcm, mask, t.cfg.Obfs.Padding)
		if err != nil {
			logDebug(fmt.Sprintf("rx from %s: %v", src, err))
			continue
		}

		t.lastPeer.Store(src)

		if _, err := tun.Write(pkt); err != nil {
			select {
			case <-t.done:
				return
			default:
				logWarn("tun write: " + err.Error())
			}
		}
	}
}

// txLoop: TUN → encrypt → UDP
// conn and tun are passed as values so they're never nil after doClean().
// Uses a pre-allocated buffer from the pool — zero per-packet allocation.
func (t *UdpObfsTunnel) txLoop(conn *net.UDPConn, tun *os.File, gcm cipher.AEAD, mask string, mtu int, fixed *net.UDPAddr) {
	buf := getBuf()
	defer putBuf(buf)
	_ = mtu
	for {
		select {
		case <-t.done:
			return
		default:
		}

		n, err := tun.Read(buf)
		if err != nil {
			select {
			case <-t.done:
				return
			default:
				logWarn("tun read: " + err.Error())
				continue
			}
		}

		frame, err := obfsEncrypt(buf[:n], gcm, mask, t.cfg.Obfs.Padding)
		if err != nil {
			logDebug("encrypt: " + err.Error())
			continue
		}

		dst := fixed
		if dst == nil {
			if p, ok := t.lastPeer.Load().(*net.UDPAddr); ok && p != nil {
				dst = p
			} else {
				continue
			}
		}

		if _, err := conn.WriteToUDP(frame, dst); err != nil {
			logDebug("udp send: " + err.Error())
		}
	}
}

func (t *UdpObfsTunnel) Down() error {
	t.doClean()
	logOK("udp-obfs torn down")
	return nil
}

func (t *UdpObfsTunnel) doClean() {
	if t.done != nil {
		select {
		case <-t.done:
		default:
			close(t.done)
		}
		t.done = nil
	}
	if t.udpConn != nil {
		t.udpConn.Close()
		t.udpConn = nil
	}
	if t.tunFd != nil {
		t.tunFd.Close()
		t.tunFd = nil
	}
	nlDown(t.DevName())
}

func (t *UdpObfsTunnel) Status() {
	if l, err := netlink.LinkByName(t.DevName()); err == nil {
		fmt.Printf("  %s: flags=%v\n", l.Attrs().Name, l.Attrs().Flags)
	}
}

// ── TUN device ────────────────────────────────────────────────────────────────

// openTunDev creates a TUN interface by name and returns its file descriptor.
// All subsequent reads/writes on the fd are raw IP packets.
// txqueuelen is set to 1000 (vs default 100) to absorb packet bursts.
func openTunDev(name string) (*os.File, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}

	// Build ifreq: name (16B) + flags (2B) + padding
	var ifr [40]byte
	copy(ifr[:16], name)
	binary.LittleEndian.PutUint16(ifr[16:], iffTun|iffNoPi)

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		tunSetIff, uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF %s: %w", name, errno)
	}
	f := os.NewFile(uintptr(fd), name)

	// Increase tx queue so userspace bursts don't cause ENOBUFS drops.
	if l, lerr := netlink.LinkByName(name); lerr == nil {
		_ = netlink.LinkSetTxQLen(l, 1000)
	}
	return f, nil
}

// ── crypto ────────────────────────────────────────────────────────────────────

// deriveObfsKey turns an arbitrary passphrase into a 32-byte AES-256 key.
func deriveObfsKey(passphrase string) [32]byte {
	return sha256.Sum256([]byte(passphrase))
}

// obfsEncrypt encrypts plaintext IP packet and prepends the chosen mask header.
// gcm is the cached cipher — created once in Up(), safe for concurrent use.
//
// Plaintext inside GCM:
//
//	[flags(1B)] [original packet] [random pad (optional)] [padLen(1B)]
//	flags: 0x01 = padding present
func obfsEncrypt(pkt []byte, gcm cipher.AEAD, mask string, padding bool) ([]byte, error) {
	// build inner plaintext
	inner := make([]byte, 1+len(pkt))
	if padding {
		padLen := int(mustRandByte()%48) + 4
		pad := make([]byte, padLen)
		if _, err := rand.Read(pad); err != nil {
			return nil, err
		}
		pad[padLen-1] = byte(padLen)
		inner = make([]byte, 1+len(pkt)+padLen)
		inner[0] = 0x01
		copy(inner[1:], pkt)
		copy(inner[1+len(pkt):], pad)
	} else {
		inner[0] = 0x00
		copy(inner[1:], pkt)
	}

	// nonce: 12-byte random (GCM standard)
	var nonceBuf [12]byte
	if _, err := rand.Read(nonceBuf[:]); err != nil {
		return nil, err
	}
	nonce := nonceBuf[:]

	// encrypt — gcm.Seal appends to nil → allocates result once
	ciphertext := gcm.Seal(nil, nonce, inner, nil)

	// build wire frame: [mask header] [nonce] [ciphertext]
	var hdr []byte
	switch mask {
	case "quic":
		h := quicPrefix
		_, _ = rand.Read(h[6:14]) // randomise DCID per packet
		hdr = h[:]
	case "dtls":
		h := dtlsPrefix
		payLen := len(nonce) + len(ciphertext)
		binary.BigEndian.PutUint16(h[11:], uint16(payLen))
		hdr = h[:]
	}

	frame := make([]byte, 0, len(hdr)+len(nonce)+len(ciphertext))
	frame = append(frame, hdr...)
	frame = append(frame, nonce...)
	frame = append(frame, ciphertext...)
	return frame, nil
}

// obfsDecrypt reverses obfsEncrypt.
// gcm is the cached cipher — same object reused across all packets.
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

	inner, err := gcm.Open(nil, frame[:ns], frame[ns:], nil)
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

func mustRandByte() byte {
	var b [1]byte
	rand.Read(b[:])
	return b[0]
}
