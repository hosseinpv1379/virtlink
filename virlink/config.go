package main

import (
	"fmt"
	"net"
	"os"

	"github.com/BurntSushi/toml"
)

// ─── TOML sections ────────────────────────────────────────────────────────────

// TunnelCfg maps to [tunnel] in config.toml
type TunnelCfg struct {
	Type     string `toml:"type"`      // gre-fou | ipip-fou | bonded-gre-fou | l2tpv3 | gre-wg | vxlan-wg | gre-fou-ipsec
	Mode     string `toml:"mode"`      // server | client
	LocalIP  string `toml:"local_ip"`  // this host's public IP
	RemoteIP string `toml:"remote_ip"` // peer's public IP
	CIDR     string `toml:"cidr"`      // overlay subnet, e.g. "10.20.10.0/24"
	                                   //   client → .1/<prefix>, server → .2/<prefix>
	Name     string `toml:"name"`      // optional custom interface name
	MTU      int    `toml:"mtu"`       // overlay MTU (auto if 0)
}

// TransportCfg maps to [transport]
type TransportCfg struct {
	Port              int    `toml:"port"`               // primary UDP port
	Port2             int    `toml:"port2"`              // secondary port (bonded only)
	Proto             string `toml:"proto"`              // informational: fou | wireguard | l2tp
	HeartbeatInterval int    `toml:"heartbeat_interval"` // seconds between status logs (default 10)
}

// WireGuardCfg maps to [wireguard]
type WireGuardCfg struct {
	ClientPrivKey string `toml:"client_private_key"`
	ClientPubKey  string `toml:"client_public_key"`
	ServerPrivKey string `toml:"server_private_key"`
	ServerPubKey  string `toml:"server_public_key"`
	VNI           int    `toml:"vni"` // VXLAN Network Identifier (vxlan-wg)
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
	BBR         bool `toml:"bbr"`          // enable BBR + fq qdisc
	Multipath   bool `toml:"multipath"`    // ECMP per-flow hashing (bonded)
	Workers     int  `toml:"workers"`      // 0 = auto (future use)
	ChannelSize int  `toml:"channel_size"` // future use
}

// LoggingCfg maps to [logging]
type LoggingCfg struct {
	Level string `toml:"level"` // debug | info | warn | error
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

// ─── root config ─────────────────────────────────────────────────────────────

type Config struct {
	// TOML sections
	Tunnel    TunnelCfg    `toml:"tunnel"`
	Transport TransportCfg `toml:"transport"`
	WireGuard WireGuardCfg `toml:"wireguard"`
	L2TP      L2TPCfg      `toml:"l2tp"`
	Security  SecurityCfg  `toml:"security"`
	Tuning    TuningCfg    `toml:"tuning"`
	Logging   LoggingCfg   `toml:"logging"`
	Forward   ForwardCfg   `toml:"forward"`
	Obfs      ObfsCfg      `toml:"obfs"`

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
	GreWg   greWgCfg   `toml:"-"`
	VxlanWg vxlanWgCfg `toml:"-"`
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

type greWgCfg struct {
	WgPort                                          int
	MTU                                             int
	ClientPrivKey, ClientPubKey                     string
	ServerPrivKey, ServerPubKey                     string
}

type vxlanWgCfg struct {
	WgPort                                          int
	VNI, MTU                                        int
	ClientPrivKey, ClientPubKey                     string
	ServerPrivKey, ServerPubKey                     string
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
	t, tr, wg, l, s := c.Tunnel, c.Transport, c.WireGuard, c.L2TP, c.Security

	c.GreFou  = greFouCfg{Port: tr.Port, MTU: t.MTU}
	c.IpipFou = ipipFouCfg{Port: tr.Port, MTU: t.MTU}
	c.Bonded  = bondedCfg{Port1: tr.Port, Port2: tr.Port2, MTU: t.MTU}
	c.L2tpv3  = l2tpv3Cfg{
		Port: tr.Port, MTU: t.MTU,
		ClientTunnelID: l.ClientTunnelID, ServerTunnelID: l.ServerTunnelID,
		ClientSessionID: l.ClientSessionID, ServerSessionID: l.ServerSessionID,
	}
	c.GreWg = greWgCfg{
		WgPort: tr.Port, MTU: t.MTU,
		ClientPrivKey: wg.ClientPrivKey, ClientPubKey: wg.ClientPubKey,
		ServerPrivKey: wg.ServerPrivKey, ServerPubKey: wg.ServerPubKey,
	}
	c.VxlanWg = vxlanWgCfg{
		WgPort: tr.Port, VNI: wg.VNI, MTU: t.MTU,
		ClientPrivKey: wg.ClientPrivKey, ClientPubKey: wg.ClientPubKey,
		ServerPrivKey: wg.ServerPrivKey, ServerPubKey: wg.ServerPubKey,
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
		case "gre-wg":          t.MTU = 1380
		case "vxlan-wg":        t.MTU = 1360
		case "gre-fou-ipsec":   t.MTU = 1380
		case "udp-obfs":        t.MTU = 1400
		default:                t.MTU = 1420
		}
	}

	if tr.Port == 0 {
		switch t.Type {
		case "gre-fou", "gre-fou-ipsec": tr.Port = 5556
		case "ipip-fou":                 tr.Port = 5055
		case "bonded-gre-fou":           tr.Port = 5557
		case "l2tpv3":                   tr.Port = 5059
		case "gre-wg":                   tr.Port = 51820
		case "vxlan-wg":                 tr.Port = 51821
		case "udp-obfs":                 tr.Port = 443   // default: looks like QUIC
		default:                         tr.Port = 5556
		}
	}
	if tr.Port2 == 0 && t.Type == "bonded-gre-fou" {
		tr.Port2 = tr.Port + 1
	}

	if c.WireGuard.VNI == 0 {
		c.WireGuard.VNI = 100
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

	if !c.Tuning.BBR { c.Tuning.BBR = true }
	if c.Tuning.ChannelSize == 0 { c.Tuning.ChannelSize = 10_000 }
	if c.Logging.Level == ""     { c.Logging.Level = "info" }
}

// ─── validation ───────────────────────────────────────────────────────────────

func validate(c *Config) error {
	t := &c.Tunnel
	if t.Mode != "client" && t.Mode != "server" {
		return fmt.Errorf("[tunnel] mode must be \"client\" or \"server\", got %q", t.Mode)
	}
	valid := []string{
		"gre-fou", "ipip-fou", "bonded-gre-fou",
		"l2tpv3", "gre-wg", "vxlan-wg", "gre-fou-ipsec",
		"udp-obfs",
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
	return nil
}
