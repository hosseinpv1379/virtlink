//go:build linux

package virlink

// tcpWireKernelUp/Down — no extra routes or lo aliases for TCP wire spoof.
// FREEBIND on the client socket sets outer src; connect() uses real remote_ip
// so packets reach the peer (same wire dst semantics as ICMP/UDP).
func tcpWireKernelUp(cfg *Config) error { return nil }
func tcpWireKernelDown(cfg *Config)       {}
