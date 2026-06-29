// Package core defines the tunnel contract and type registry.
package core

// Tunnel manages a virtual link.
type Tunnel interface {
	Up() error
	Down() error
	Status()
	DevName() string
	OverlayIP() string
	PeerIP() string
}
