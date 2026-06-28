//go:build !linux

package virlink

func tcpWireKernelUp(cfg *Config) error { return nil }
func tcpWireKernelDown(cfg *Config)     {}
