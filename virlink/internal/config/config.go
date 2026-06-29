// config.go — TOML config types, load, validate, defaults.
package config

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
	Type     string `toml:"type"`
	Mode     string `toml:"mode"`
	LocalIP  string `toml:"local_ip"`
	RemoteIP string `toml:"remote_ip"`
	CIDR     string `toml:"cidr"`
	Name     string `toml:"name"`
	MTU      int    `toml:"mtu"`
}

// TransportCfg maps to [transport]
type TransportCfg struct {
	Port              int    `toml:"port"`
	Port2             int    `toml:"port2"`
	Proto             string `toml:"proto"`
	HeartbeatInterval int    `toml:"heartbeat_interval"`
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
	Encryption bool   `toml:"encryption"`
	SpiOut     string `toml:"spi_out"`
	SpiIn      string `toml:"spi_in"`
	EncKeyOut  string `toml:"enc_key_out"`
	EncKeyIn   string `toml:"enc_key_in"`
	AuthKeyOut string `toml:"auth_key_out"`
	AuthKeyIn  string `toml:"auth_key_in"`
}

// TuningCfg maps to [tuning]
type TuningCfg struct {
	Enabled     *bool  `toml:"enabled"`
	Mode        string `toml:"mode"`
	Multipath   bool   `toml:"multipath"`
	SockBufMB   int    `toml:"sock_buf_mb"`
	TunQueues   int    `toml:"tun_queues"`
	BatchSize   int    `toml:"batch_size"`
	TxQLen      int    `toml:"tx_queue_len"`
	PollMs      int    `toml:"poll_ms"`
	TcpStreams  int    `toml:"tcp_streams"`
	Workers     int    `toml:"workers"`
	ChannelSize int    `toml:"channel_size"`
	BBR         bool   `toml:"bbr"`
}

// LoggingCfg maps to [logging]
type LoggingCfg struct {
	Level           string `toml:"level"`
	Profile         bool   `toml:"profile"`
	ProfileInterval int    `toml:"profile_interval"`
}

// ObfsCfg maps to [obfs]
type ObfsCfg struct {
	Key     string `toml:"key"`
	Mask    string `toml:"mask"`
	Padding bool   `toml:"padding"`
}

// ForwardCfg maps to [forward]
type ForwardCfg struct {
	Enabled bool     `toml:"enabled"`
	Rules   []string `toml:"rules"`
}

// HealthCfg maps to [health]
type HealthCfg struct {
	Disabled bool `toml:"disabled"`
	Port     int  `toml:"port"`
	HTTPPort int  `toml:"http_port"`
}

// OpenVPNCfg maps to [openvpn]
type OpenVPNCfg struct {
	Config  string `toml:"config"`
	Dev     string `toml:"dev"`
	Workers int    `toml:"workers"`
	DCO     *bool  `toml:"dco"`
}

// OpenVPNMultuCfg maps to [openvpnmultu]
type OpenVPNMultuCfg struct {
	PKIDir  string `toml:"pki_dir"`
	Workers int    `toml:"workers"`
}

// Hysteria2Cfg maps to [hysteria2]
type Hysteria2Cfg struct {
	Config string `toml:"config"`
	Dev    string `toml:"dev"`
}

// WireGuardCfg maps to [wireguard]
type WireGuardCfg struct {
	Config string `toml:"config"`
	Dev    string `toml:"dev"`
}

// TcpMuxCfg maps to [tcpmux]
type TcpMuxCfg struct {
	Hash string `toml:"hash"`
}

// AmneziaWGCfg maps to [amneziawg]
type AmneziaWGCfg struct {
	Config string `toml:"config"`
	Dev    string `toml:"dev"`
}

// MangleCfg maps to [mangle]
type MangleCfg struct {
	SrcIP string `toml:"srcip"`
	DstIP string `toml:"dstip"`
}

// Config is the root TOML configuration.
type Config struct {
	Tunnel       TunnelCfg       `toml:"tunnel"`
	Transport    TransportCfg    `toml:"transport"`
	L2TP         L2TPCfg         `toml:"l2tp"`
	Security     SecurityCfg     `toml:"security"`
	Tuning       TuningCfg       `toml:"tuning"`
	Logging      LoggingCfg      `toml:"logging"`
	Forward      ForwardCfg      `toml:"forward"`
	Obfs         ObfsCfg         `toml:"obfs"`
	Health       HealthCfg       `toml:"health"`
	Mangle       MangleCfg       `toml:"mangle"`
	OpenVPN      OpenVPNCfg      `toml:"openvpn"`
	OpenVPNMultu OpenVPNMultuCfg `toml:"openvpnmultu"`
	Hysteria2    Hysteria2Cfg    `toml:"hysteria2"`
	WireGuard    WireGuardCfg    `toml:"wireguard"`
	TcpMux       TcpMuxCfg       `toml:"tcpmux"`
	AmneziaWG    AmneziaWGCfg    `toml:"amneziawg"`

	Mode     string `toml:"-"`
	LocalIP  string `toml:"-"`
	RemoteIP string `toml:"-"`

	GreFou  GreFouCfg  `toml:"-"`
	IpipFou IpipFouCfg `toml:"-"`
	Bonded  BondedCfg  `toml:"-"`
	L2tpv3  L2tpv3Cfg  `toml:"-"`
	Ipsec   IpsecCfg   `toml:"-"`
}

type GreFouCfg struct{ Port, MTU int }
type IpipFouCfg struct{ Port, MTU int }
type BondedCfg struct{ Port1, Port2, MTU int }

type L2tpv3Cfg struct {
	Port                             int
	ClientTunnelID, ServerTunnelID   int
	ClientSessionID, ServerSessionID int
	MTU                              int
}

type IpsecCfg struct {
	Port                   int
	MTU                    int
	SpiOut, SpiIn          string
	EncKeyOut, EncKeyIn    string
	AuthKeyOut, AuthKeyIn  string
}

// Load reads and validates a config file.
func Load(path string) (*Config, error) {
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
	cfg.Mode = cfg.Tunnel.Mode
	cfg.LocalIP = cfg.Tunnel.LocalIP
	cfg.RemoteIP = cfg.Tunnel.RemoteIP
	cfg.shim()
	return &cfg, nil
}

func (c *Config) shim() {
	t, tr, l, s := c.Tunnel, c.Transport, c.L2TP, c.Security

	c.GreFou = GreFouCfg{Port: tr.Port, MTU: t.MTU}
	c.IpipFou = IpipFouCfg{Port: tr.Port, MTU: t.MTU}
	c.Bonded = BondedCfg{Port1: tr.Port, Port2: tr.Port2, MTU: t.MTU}
	c.L2tpv3 = L2tpv3Cfg{
		Port: tr.Port, MTU: t.MTU,
		ClientTunnelID: l.ClientTunnelID, ServerTunnelID: l.ServerTunnelID,
		ClientSessionID: l.ClientSessionID, ServerSessionID: l.ServerSessionID,
	}
	c.Ipsec = IpsecCfg{
		Port: tr.Port, MTU: t.MTU,
		SpiOut: s.SpiOut, SpiIn: s.SpiIn,
		EncKeyOut: s.EncKeyOut, EncKeyIn: s.EncKeyIn,
		AuthKeyOut: s.AuthKeyOut, AuthKeyIn: s.AuthKeyIn,
	}
}

func setDefaults(c *Config) {
	t := &c.Tunnel
	tr := &c.Transport

	if t.MTU == 0 {
		switch t.Type {
		case "gre-fou":
			t.MTU = 1420
		case "ipip-fou":
			t.MTU = 1440
		case "bonded-gre-fou":
			t.MTU = 1400
		case "l2tpv3":
			t.MTU = 1464
		case "gre-fou-ipsec":
			t.MTU = 1380
		case "udp-obfs":
			t.MTU = 1400
		case "gre":
			t.MTU = 1476
		case "tcp":
			t.MTU = 1460
		case "tcpmux":
			t.MTU = 1460
		case "udp":
			t.MTU = 1472
		case "icmp":
			t.MTU = 1472
		case "bip":
			t.MTU = 1480
		case "hysteria2":
			t.MTU = 1400
		case "wireguard":
			t.MTU = 1420
		case "amneziawg":
			t.MTU = 1420
		default:
			t.MTU = 1420
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
		case "gre-fou", "gre-fou-ipsec":
			tr.Port = 5556
		case "ipip-fou":
			tr.Port = 5055
		case "bonded-gre-fou":
			tr.Port = 5557
		case "l2tpv3":
			tr.Port = 5059
		case "udp-obfs":
			tr.Port = 443
		case "tcp", "tcpmux":
			tr.Port = 8443
		case "openvpn", "openvpnmultu":
			tr.Port = 1194
		case "hysteria2":
			tr.Port = 443
		case "wireguard":
			tr.Port = 51820
		case "amneziawg":
			tr.Port = 51820
		case "udp":
			tr.Port = 5060
		default:
			tr.Port = 5556
		}
	}
	if tr.Port2 == 0 && t.Type == "bonded-gre-fou" {
		tr.Port2 = tr.Port + 1
	}
	if c.OpenVPN.Dev == "" && t.Type == "openvpn" {
		c.OpenVPN.Dev = TunnelDevName(c, "ovpn-tun0")
	}
	if c.Hysteria2.Dev == "" && t.Type == "hysteria2" {
		c.Hysteria2.Dev = TunnelDevName(c, "hy2-tun0")
	}
	if c.WireGuard.Dev == "" && t.Type == "wireguard" {
		c.WireGuard.Dev = TunnelDevName(c, "wg-virlink0")
	}
	if c.AmneziaWG.Dev == "" && t.Type == "amneziawg" {
		c.AmneziaWG.Dev = TunnelDevName(c, "awg-virlink0")
	}

	l := &c.L2TP
	if l.ClientTunnelID == 0 {
		l.ClientTunnelID = 1000
	}
	if l.ServerTunnelID == 0 {
		l.ServerTunnelID = 2000
	}
	if l.ClientSessionID == 0 {
		l.ClientSessionID = 1000
	}
	if l.ServerSessionID == 0 {
		l.ServerSessionID = 2000
	}

	s := &c.Security
	if s.SpiOut == "" {
		s.SpiOut = "0x00000001"
	}
	if s.SpiIn == "" {
		s.SpiIn = "0x00000002"
	}
	if s.EncKeyOut == "" {
		s.EncKeyOut = "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	}
	if s.EncKeyIn == "" {
		s.EncKeyIn = "0x2f2e2d2c2b2a29282726252423222120201f1e1d1c1b1a191817161514131211"
	}
	if s.AuthKeyOut == "" {
		s.AuthKeyOut = "0xa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
	}
	if s.AuthKeyIn == "" {
		s.AuthKeyIn = "0xb2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1"
	}

	if c.TcpMux.Hash == "" && t.Type == "tcpmux" {
		c.TcpMux.Hash = "fnv1a"
	}

	if c.Tuning.Mode == "" {
		if t.Type == "openvpn" || t.Type == "hysteria2" || t.Type == "wireguard" || t.Type == "amneziawg" {
			c.Tuning.Mode = "fast"
		} else {
			c.Tuning.Mode = "balanced"
		}
	}
	if c.Tuning.ChannelSize == 0 {
		c.Tuning.ChannelSize = 10_000
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if t.Type == "hysteria2" {
		c.Health.Disabled = true
	}
}

func validate(c *Config) error {
	t := &c.Tunnel
	if t.Mode != "client" && t.Mode != "server" {
		return fmt.Errorf("[tunnel] mode must be \"client\" or \"server\", got %q", t.Mode)
	}
	valid := []string{
		"gre-fou", "ipip-fou", "bonded-gre-fou",
		"l2tpv3", "gre-fou-ipsec",
		"udp-obfs",
		"gre", "tcp", "tcpmux", "udp", "icmp", "bip", "openvpn", "openvpnmultu", "hysteria2", "wireguard", "amneziawg",
	}
	ok := false
	for _, v := range valid {
		if t.Type == v {
			ok = true
			break
		}
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
	return nil
}
