package core

// Meta holds per-tunnel defaults and classification (replaces hardcoded switches).
type Meta struct {
	DefaultMTU        int
	DefaultPort       int // 0 = no transport port
	DefaultPort2Delta int // bonded: port2 = port + delta
	Userspace         bool
	TcpUserspace      bool
	Kernel            bool
	DefaultTuningFast bool // openvpn/hysteria2/wg use fast tuning by default
	DisableHealth     bool
}
