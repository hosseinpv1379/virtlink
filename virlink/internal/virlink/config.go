// config.go — TOML config types, load, validate, defaults.
package virlink

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// ─── TOML sections ────────────────────────────────────────────────────────────

// TunnelCfg maps to [tunnel] in config.toml
type TunnelCfg struct {
	Type     string `toml:"type"`      // gre-fou | ipip-fou | bonded-gre-fou | l2tpv3 | gre-fou-ipsec | ...
	Mode     string `toml:"mode"`      // server | client
	LocalIP  string `toml:"local_ip"`  // this host's public IP
	RemoteIP string `toml:"remote_ip"` // peer's public IP
	CIDR     string `toml:"cidr"`      // overlay subnet, e.g. "10.20.10.0/24"
	                                   //   client → .1/<prefix>, server → .2/<prefix>
	Name     string `toml:"name"`      // tunnel id; also default Linux interface name (IFNAME)
	MTU      int    `toml:"mtu"`       // overlay MTU (auto if 0)
}

// TransportCfg maps to [transport]
type TransportCfg struct {
	Port              int    `toml:"port"`               // primary UDP port
	Port2             int    `toml:"port2"`              // secondary port (bonded only)
	Proto             string `toml:"proto"`              // informational: fou | l2tp
	HeartbeatInterval int    `toml:"heartbeat_interval"` // seconds between status logs (default 10)
}

// L2TPCfg maps to [l2tp]
type L2TPCfg struct {
	ClientTunnelID  int `toml:"client_tunnel_id"`
	ServerTunnelID  int `toml:"server_tunnel_id"`
	ClientSessionID int `toml:"client_session_id"`
	ServerSessionID int `toml:"server_session_id"`
}

// SecurityCfg maps to [security]
type SecurityCfg struct {
	Encryption bool   `toml:"encryption"`   // informational flag
	SpiOut     string `toml:"spi_out"`       // IPsec SA SPI outbound
	SpiIn      string `toml:"spi_in"`        // IPsec SA SPI inbound
	EncKeyOut  string `toml:"enc_key_out"`   // AES-256 key outbound
	EncKeyIn   string `toml:"enc_key_in"`
	AuthKeyOut string `toml:"auth_key_out"`  // HMAC-SHA256 key outbound
	AuthKeyIn  string `toml:"auth_key_in"`
}

// TuningCfg maps to [tuning]
type TuningCfg struct {
	Enabled     *bool  `toml:"enabled"` // default true — scoped sysctl at tunnel up
	Mode        string `toml:"mode"`    // balanced | fast | resource | latency
	Multipath   bool   `toml:"multipath"`
	// ── performance knobs (0 = default) ─────────────────────────────────────
	SockBufMB   int `toml:"sock_buf_mb"`    // socket SO_RCVBUF/SO_SNDBUF in MB (default 32)
	TunQueues   int `toml:"tun_queues"`     // IFF_MULTI_QUEUE readers (default 4, max 16)
	BatchSize   int `toml:"batch_size"`     // ICMP sendmmsg batch count (default 32, max 128)
	TxQLen      int `toml:"tx_queue_len"`   // TUN interface txqueuelen (default from mode)
	PollMs      int `toml:"poll_ms"`        // I/O poll timeout ms (default 10)
	TcpStreams  int `toml:"tcp_streams"`    // TCP/tcpmux parallel streams (default 4–8 by CPU; not tied to tun_queues)
	Workers     int `toml:"workers"`        // reserved
	ChannelSize int `toml:"channel_size"`   // reserved (legacy)
	BBR         bool `toml:"bbr"`           // legacy; mode takes precedence
}

// LoggingCfg maps to [logging]
type LoggingCfg struct {
	Level           string `toml:"level"`            // debug | info | warn | error
	Profile         bool   `toml:"profile"`          // periodic CPU activity report
	ProfileInterval int    `toml:"profile_interval"` // seconds between reports (default 30)
}

// ObfsCfg maps to [obfs] — shared crypto config for udp-obfs tunnel.
type ObfsCfg struct {
	Key     string `toml:"key"`     // shared passphrase (both sides must match)
	Mask    string `toml:"mask"`    // "noise" (default) | "quic" | "dtls"
	Padding bool   `toml:"padding"` // add random-length padding to defeat length analysis
}

// ForwardCfg maps to [forward] — client-only port forwarding via iptables DNAT.
// Rules format: "listenPort:targetPort"  or  "listenPort:targetPort/tcp"
//   "1000:2000"      → :1000 (tcp+udp) → peerIP:2000
//   "8080:80/tcp"    → :8080 (tcp only) → peerIP:80
type ForwardCfg struct {
	Enabled bool     `toml:"enabled"`
	Rules   []string `toml:"rules"`
}

// HealthCfg maps to [health].
// UDP probe + HTTP endpoint to verify real end-to-end connectivity.
type HealthCfg struct {
	Disabled bool `toml:"disabled"` // set to true to disable (default: enabled)
	Port     int  `toml:"port"`     // UDP probe port (default 6543 + per-tunnel offset)
	HTTPPort int  `toml:"http_port"` // web panel + /health /bench API (default 6543 on overlay IP)
}

// OpenVPNCfg maps to [openvpn]
type OpenVPNCfg struct {
	Config  string `toml:"config"`  // path to openvpn .conf (worker 0; others use -N suffix)
	Dev     string `toml:"dev"`     // TUN name (must match dev in .conf, default ovpn-tun0)
	Workers int    `toml:"workers"` // deprecated — ignored; use dco for multi-core on one overlay IP
	DCO     *bool  `toml:"dco"`     // nil=auto, true=force enable-dco, false=disable
}

// OpenVPNMultuCfg maps to [openvpnmultu] — N parallel openvpn + ECMP load-balancing.
type OpenVPNMultuCfg struct {
	PKIDir  string `toml:"pki_dir"`  // PKI directory (ca.crt, server.crt, …); worker .conf generated at runtime
	Workers int    `toml:"workers"`  // parallel openvpn instances (2–8)
}

// Hysteria2Cfg maps to [hysteria2]
type Hysteria2Cfg struct {
	Config string `toml:"config"` // path to hysteria2 YAML config
	Dev    string `toml:"dev"`    // TUN name (default hy2-tun0)
}

// WireGuardCfg maps to [wireguard]
type WireGuardCfg struct {
	Config string `toml:"config"` // path to wg-quick-style .conf file
	Dev    string `toml:"dev"`    // interface name (default wg-virlink0)
}

// TcpMuxCfg maps to [tcpmux] — flow-hash multiplexed TCP tunnel.
type TcpMuxCfg struct {
	Hash string `toml:"hash"` // fnv1a (default), 0x hex seed, decimal, or salt string
}

// AmneziaWGCfg maps to [amneziawg] — obfuscated WireGuard (awg + amneziawg kernel module).
type AmneziaWGCfg struct {
	Config string `toml:"config"` // path to awg-quick-style .conf file
	Dev    string `toml:"dev"`    // interface name (default awg-virlink0)
}

// MangleCfg maps to [mangle] — optional wire IP spoof (manual config only).
// Userspace (icmp/udp/bip): IP_HDRINCL  ·  Kernel (gre-fou, gre, …): nftables mangle
// Client: srcip=1.1.1.1 dstip=2.2.2.2  ·  Server: srcip=2.2.2.2 dstip=1.1.1.1
type MangleCfg struct {
	SrcIP string `toml:"srcip"`
	DstIP string `toml:"dstip"`
}

// ─── root config ─────────────────────────────────────────────────────────────

type Config struct {
	// TOML sections
	Tunnel    TunnelCfg    `toml:"tunnel"`
	Transport TransportCfg `toml:"transport"`
	L2TP      L2TPCfg      `toml:"l2tp"`
	Security  SecurityCfg  `toml:"security"`
	Tuning    TuningCfg    `toml:"tuning"`
	Logging   LoggingCfg   `toml:"logging"`
	Forward   ForwardCfg   `toml:"forward"`
	Obfs      ObfsCfg      `toml:"obfs"`
	Health    HealthCfg    `toml:"health"`
	Mangle    MangleCfg    `toml:"mangle"`
	OpenVPN       OpenVPNCfg       `toml:"openvpn"`
	OpenVPNMultu  OpenVPNMultuCfg  `toml:"openvpnmultu"`
	Hysteria2 Hysteria2Cfg `toml:"hysteria2"`
	WireGuard WireGuardCfg `toml:"wireguard"`
	TcpMux    TcpMuxCfg    `toml:"tcpmux"`
	AmneziaWG AmneziaWGCfg `toml:"amneziawg"`

	// Convenience aliases (set after parse, not from TOML)
	Mode     string `toml:"-"`
	LocalIP  string `toml:"-"`
	RemoteIP string `toml:"-"`

	// Shim fields — tunnel implementations read these.
	// Populated by shim() so tun_*.go don't need to change.
	GreFou  greFouCfg  `toml:"-"`
	IpipFou ipipFouCfg `toml:"-"`
	Bonded  bondedCfg  `toml:"-"`
	L2tpv3  l2tpv3Cfg  `toml:"-"`
	Ipsec   ipsecCfg   `toml:"-"`
}

// ─── shim types (used by tun_*.go) ───────────────────────────────────────────

type greFouCfg  struct{ Port, MTU int }
type ipipFouCfg struct{ Port, MTU int }
type bondedCfg  struct{ Port1, Port2, MTU int }

type l2tpv3Cfg struct {
	Port                                            int
	ClientTunnelID, ServerTunnelID                  int
	ClientSessionID, ServerSessionID                int
	MTU                                             int
}

type ipsecCfg struct {
	Port                                            int
	MTU                                             int
	SpiOut, SpiIn                                   string
	EncKeyOut, EncKeyIn                             string
	AuthKeyOut, AuthKeyIn                           string
}

// ─── load + validate ──────────────────────────────────────────────────────────

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg Config
	if _, err := toml.Decode(string(data), &cfg); err != nil {
		return nil, fmt.Errorf("parse toml: %w", err)
	}
	if cfg.Tunnel.Name == "" {
		base := filepath.Base(path)
		if strings.HasSuffix(base, ".toml") {
			cfg.Tunnel.Name = strings.TrimSuffix(base, ".toml")
		}
	}
	setDefaults(&cfg)
	if err := validate(&cfg); err != nil {
		return nil, err
	}
	// expose root-level aliases
	cfg.Mode = cfg.Tunnel.Mode
	cfg.LocalIP = cfg.Tunnel.LocalIP
	cfg.RemoteIP = cfg.Tunnel.RemoteIP
	// fill shim fields that tun_*.go read
	cfg.shim()
	return &cfg, nil
}

// shim copies unified config sections into the per-tunnel shim structs.
func (c *Config) shim() {
	t, tr, l, s := c.Tunnel, c.Transport, c.L2TP, c.Security

	c.GreFou  = greFouCfg{Port: tr.Port, MTU: t.MTU}
	c.IpipFou = ipipFouCfg{Port: tr.Port, MTU: t.MTU}
	c.Bonded  = bondedCfg{Port1: tr.Port, Port2: tr.Port2, MTU: t.MTU}
	c.L2tpv3  = l2tpv3Cfg{
		Port: tr.Port, MTU: t.MTU,
		ClientTunnelID: l.ClientTunnelID, ServerTunnelID: l.ServerTunnelID,
		ClientSessionID: l.ClientSessionID, ServerSessionID: l.ServerSessionID,
	}
	c.Ipsec = ipsecCfg{
		Port: tr.Port, MTU: t.MTU,
		SpiOut: s.SpiOut, SpiIn: s.SpiIn,
		EncKeyOut: s.EncKeyOut, EncKeyIn: s.EncKeyIn,
		AuthKeyOut: s.AuthKeyOut, AuthKeyIn: s.AuthKeyIn,
	}
}

// ─── defaults ─────────────────────────────────────────────────────────────────

func setDefaults(c *Config) {
	t := &c.Tunnel
	tr := &c.Transport

	if t.MTU == 0 {
		switch t.Type {
		case "gre-fou":         t.MTU = 1420
		case "ipip-fou":        t.MTU = 1440
		case "bonded-gre-fou":  t.MTU = 1400
		case "l2tpv3":          t.MTU = 1464
		case "gre-fou-ipsec":   t.MTU = 1380
		case "udp-obfs":        t.MTU = 1400
		case "gre":             t.MTU = 1476
		case "tcp":             t.MTU = 1460
		case "tcpmux":          t.MTU = 1460
		case "udp":             t.MTU = 1472
		case "icmp":            t.MTU = 1472
		case "bip":             t.MTU = 1480
		case "hysteria2":       t.MTU = 1400
		case "wireguard":       t.MTU = 1420
		case "amneziawg":      t.MTU = 1420
		default:                t.MTU = 1420
		}
	}
	if tr.Proto == "" && (t.Type == "openvpn" || t.Type == "openvpnmultu" || t.Type == "hysteria2" || t.Type == "wireguard" || t.Type == "amneziawg") {
		tr.Proto = "udp"
	}
	if t.MTU == 0 && (t.Type == "openvpn" || t.Type == "openvpnmultu") {
		if tr.Proto == "tcp" {
			t.MTU = 1400
		} else {
			t.MTU = 1472
		}
	}

	if tr.Port == 0 {
		switch t.Type {
		case "gre-fou", "gre-fou-ipsec": tr.Port = 5556
		case "ipip-fou":                 tr.Port = 5055
		case "bonded-gre-fou":           tr.Port = 5557
		case "l2tpv3":                   tr.Port = 5059
		case "udp-obfs":                 tr.Port = 443
		case "tcp", "tcpmux":            tr.Port = 8443
		case "openvpn", "openvpnmultu": tr.Port = 1194
		case "hysteria2":                tr.Port = 443
		case "wireguard":                tr.Port = 51820
		case "amneziawg":                tr.Port = 51820
		case "udp":                      tr.Port = 5060
		// gre, icmp, bip don't use ports (raw protocol tunnels)
		default:                         tr.Port = 5556
		}
	}
	if tr.Port2 == 0 && t.Type == "bonded-gre-fou" {
		tr.Port2 = tr.Port + 1
	}
	if c.OpenVPN.Dev == "" && t.Type == "openvpn" {
		c.OpenVPN.Dev = tunnelDevName(c, "ovpn-tun0")
	}
	if c.Hysteria2.Dev == "" && t.Type == "hysteria2" {
		c.Hysteria2.Dev = tunnelDevName(c, "hy2-tun0")
	}
	if c.WireGuard.Dev == "" && t.Type == "wireguard" {
		c.WireGuard.Dev = tunnelDevName(c, "wg-virlink0")
	}
	if c.AmneziaWG.Dev == "" && t.Type == "amneziawg" {
		c.AmneziaWG.Dev = tunnelDevName(c, "awg-virlink0")
	}

	l := &c.L2TP
	if l.ClientTunnelID == 0  { l.ClientTunnelID = 1000 }
	if l.ServerTunnelID == 0  { l.ServerTunnelID = 2000 }
	if l.ClientSessionID == 0 { l.ClientSessionID = 1000 }
	if l.ServerSessionID == 0 { l.ServerSessionID = 2000 }

	s := &c.Security
	if s.SpiOut == ""     { s.SpiOut = "0x00000001" }
	if s.SpiIn == ""      { s.SpiIn = "0x00000002" }
	if s.EncKeyOut == ""  { s.EncKeyOut = "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" }
	if s.EncKeyIn == ""   { s.EncKeyIn = "0x2f2e2d2c2b2a29282726252423222120201f1e1d1c1b1a191817161514131211" }
	if s.AuthKeyOut == "" { s.AuthKeyOut = "0xa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2" }
	if s.AuthKeyIn == ""  { s.AuthKeyIn = "0xb2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1" }

	if c.TcpMux.Hash == "" && t.Type == "tcpmux" {
		c.TcpMux.Hash = "fnv1a"
	}

	if c.Tuning.Mode == "" {
		if t.Type == "openvpn" || t.Type == "hysteria2" || t.Type == "wireguard" || t.Type == "amneziawg" {
			c.Tuning.Mode = tuningFast
		} else {
			c.Tuning.Mode = tuningBalanced
		}
	}
	if c.Tuning.ChannelSize == 0 { c.Tuning.ChannelSize = 10_000 }
	if c.Logging.Level == ""     { c.Logging.Level = "info" }
	applyHealthPort(c)
	applyHealthHTTPPort(c)
	if t.Type == "hysteria2"     { c.Health.Disabled = true }
}

// ─── validation ───────────────────────────────────────────────────────────────

func validate(c *Config) error {
	t := &c.Tunnel
	if t.Mode != "client" && t.Mode != "server" {
		return fmt.Errorf("[tunnel] mode must be \"client\" or \"server\", got %q", t.Mode)
	}
	valid := []string{
		"gre-fou", "ipip-fou", "bonded-gre-fou",
		"l2tpv3", "gre-fou-ipsec",
		"udp-obfs",
		// raw protocol tunnels
		"gre", "tcp", "tcpmux", "udp", "icmp", "bip", "openvpn", "openvpnmultu", "hysteria2", "wireguard", "amneziawg",
	}
	ok := false
	for _, v := range valid {
		if t.Type == v { ok = true; break }
	}
	if !ok {
		return fmt.Errorf("[tunnel] type %q not valid — choose: %v", t.Type, valid)
	}
	if net.ParseIP(t.LocalIP) == nil {
		return fmt.Errorf("[tunnel] local_ip %q is not a valid IP", t.LocalIP)
	}
	if net.ParseIP(t.RemoteIP) == nil {
		return fmt.Errorf("[tunnel] remote_ip %q is not a valid IP", t.RemoteIP)
	}
	if t.LocalIP == t.RemoteIP {
		return fmt.Errorf("[tunnel] local_ip and remote_ip must be different")
	}
	if err := validateTuningMode(tuningMode(c)); err != nil {
		return err
	}
	if err := validatePerf(&c.Tuning); err != nil {
		return err
	}
	if err := validateMangle(&c.Mangle); err != nil {
		return err
	}
	if wireSpoofEnabled(c) {
		if err := validateWireSpoofTunnel(c.Tunnel.Type); err != nil {
			return err
		}
	}
	if c.Tunnel.Type == "openvpnmultu" {
		if c.OpenVPNMultu.PKIDir == "" {
			return fmt.Errorf("[openvpnmultu] pki_dir is required")
		}
		if c.OpenVPNMultu.Workers < 2 || c.OpenVPNMultu.Workers > 8 {
			return fmt.Errorf("[openvpnmultu] workers must be 2–8, got %d", c.OpenVPNMultu.Workers)
		}
	}
	if c.Tunnel.Type == "openvpn" {
		if c.OpenVPN.Config == "" {
			return fmt.Errorf("[openvpn] config path is required")
		}
	}
	if c.Tunnel.Type == "hysteria2" {
		if c.Hysteria2.Config == "" {
			return fmt.Errorf("[hysteria2] config path is required")
		}
	}
	if c.Tunnel.Type == "wireguard" {
		if c.WireGuard.Config == "" {
			return fmt.Errorf("[wireguard] config path is required")
		}
	}
	if c.Tunnel.Type == "amneziawg" {
		if c.AmneziaWG.Config == "" {
			return fmt.Errorf("[amneziawg] config path is required")
		}
	}
	return nil
}
