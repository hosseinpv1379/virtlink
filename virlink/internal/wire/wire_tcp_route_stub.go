//go:build !linux

package wire

import "virlink/internal/config"

func TcpWireKernelUp(cfg *config.Config) error { return nil }
func TcpWireKernelDown(cfg *config.Config)     {}
