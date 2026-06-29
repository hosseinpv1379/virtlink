//go:build linux

package wire

import "virlink/internal/config"

// TcpWireKernelUp/Down — TCP wire relay uses nft input/output only (like GRE).
func TcpWireKernelUp(cfg *config.Config) error { return nil }
func TcpWireKernelDown(cfg *config.Config)       {}
