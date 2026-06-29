package core

import (
	"fmt"
	"sort"

	"virlink/internal/config"
)

// Factory builds a Tunnel from loaded config.
type Factory func(cfg *config.Config) (Tunnel, error)

type entry struct {
	meta    Meta
	factory Factory
}

var registry = map[string]entry{}

// Register adds a tunnel type. Called from each protocol package init().
func Register(name string, meta Meta, factory Factory) {
	if name == "" || factory == nil {
		panic("core.Register: name and factory required")
	}
	if _, dup := registry[name]; dup {
		panic("core.Register: duplicate type " + name)
	}
	registry[name] = entry{meta: meta, factory: factory}
}

// New creates the tunnel implementation for cfg.Tunnel.Type.
func New(cfg *config.Config) (Tunnel, error) {
	e, ok := registry[cfg.Tunnel.Type]
	if !ok {
		return nil, fmt.Errorf("unknown tunnel type: %s", cfg.Tunnel.Type)
	}
	return e.factory(cfg)
}

// Meta returns registered metadata for a type (nil if unknown).
func MetaFor(typ string) *Meta {
	e, ok := registry[typ]
	if !ok {
		return nil
	}
	m := e.meta
	return &m
}

// KnownTypes returns sorted registered tunnel type names.
func KnownTypes() []string {
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// IsUserspace reports whether typ is a userspace TUN tunnel.
func IsUserspace(typ string) bool {
	if m := MetaFor(typ); m != nil {
		return m.Userspace
	}
	return false
}

// IsTcpUserspace reports tcp / tcpmux.
func IsTcpUserspace(typ string) bool {
	if m := MetaFor(typ); m != nil {
		return m.TcpUserspace
	}
	return false
}

// IsKernel reports kernel netlink tunnels (gre-fou, l2tpv3, …).
func IsKernel(typ string) bool {
	if m := MetaFor(typ); m != nil {
		return m.Kernel
	}
	return false
}
