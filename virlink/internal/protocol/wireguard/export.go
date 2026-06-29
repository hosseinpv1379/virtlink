package wireguard

import (
	"time"

	"virlink/internal/config"
)

func ParseWireGuardConf(path string) (*WgConf, error) {
	return parseWireGuardConf(path)
}

func FirstWireGuardAddress(conf *WgConf) string {
	return firstWireGuardAddress(conf)
}

func WireguardPeerIPSubnet(conf *WgConf, c *config.Config, fallback string) string {
	return wireguardPeerIPSubnet(conf, c, fallback)
}

func LogWireGuardStatus(dev, mode, wgCmd string) {
	logWireGuardStatus(dev, mode, wgCmd)
}

func WaitForWireGuardHandshake(dev, wgCmd string, timeout time.Duration) error {
	return waitForWireGuardHandshake(dev, wgCmd, timeout)
}
