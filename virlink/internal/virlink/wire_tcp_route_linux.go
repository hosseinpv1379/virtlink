//go:build linux

package virlink

// tcpWireKernelUp/Down — TCP wire relay uses nft input/output only (like GRE).
func tcpWireKernelUp(cfg *Config) error { return nil }
func tcpWireKernelDown(cfg *Config)       {}
