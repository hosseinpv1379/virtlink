// Package register imports all tunnel protocol implementations for side-effect registration.
package register

import (
	_ "virlink/internal/protocol/amneziawg"
	_ "virlink/internal/protocol/bip"
	_ "virlink/internal/protocol/hysteria2"
	_ "virlink/internal/protocol/icmp"
	_ "virlink/internal/protocol/kernel"
	_ "virlink/internal/protocol/openvpn"
	_ "virlink/internal/protocol/openvpnmultu"
	_ "virlink/internal/protocol/tcp"
	_ "virlink/internal/protocol/tcpmux"
	_ "virlink/internal/protocol/udp"
	_ "virlink/internal/protocol/udpobfs"
	_ "virlink/internal/protocol/wireguard"
)
