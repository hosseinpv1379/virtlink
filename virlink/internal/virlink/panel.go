// panel.go — web panel helpers: list virlink tunnel interfaces + per-link stats.
package virlink

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

const defaultHTTPPanelPort = 6543

func applyHealthHTTPPort(c *Config) {
	if c.Health.HTTPPort == 0 {
		c.Health.HTTPPort = defaultHTTPPanelPort
	}
}

type ifaceJSON struct {
	Name    string `json:"name"`
	Label   string `json:"label,omitempty"`
	Kind    string `json:"kind"` // worker | tunnel | overlay
	LinkUp  bool   `json:"link_up"`
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
	RxPkts  uint64 `json:"rx_packets"`
	TxPkts  uint64 `json:"tx_packets"`
	MTU     int    `json:"mtu,omitempty"`
}

// MonitorDevs lists interfaces shown in the web panel for this tunnel.
type MonitorDevs interface {
	MonitorDevs() []string
}

// BenchRouteCtl temporarily routes overlay traffic via one worker for isolated bench.
type BenchRouteCtl interface {
	BenchIsolate(dev string) (restore func(), err error)
}

func tunnelMonitorDevs(tun Tunnel) []string {
	if m, ok := tun.(MonitorDevs); ok {
		return m.MonitorDevs()
	}
	if d := tun.DevName(); d != "" {
		return []string{d}
	}
	return nil
}

func collectIfaceStats(names []string, overlayPlain string) []ifaceJSON {
	out := make([]ifaceJSON, 0, len(names)+1)
	seen := map[string]struct{}{}

	if overlayPlain != "" {
		out = append(out, ifaceStatOne("lo", overlayPlain+" (overlay)", "overlay"))
		seen["lo"] = struct{}{}
	}
	for _, name := range names {
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		kind := "tunnel"
		if len(names) > 1 {
			kind = "worker"
		}
		out = append(out, ifaceStatOne(name, "", kind))
	}
	return out
}

func ifaceStatOne(name, label, kind string) ifaceJSON {
	row := ifaceJSON{Name: name, Label: label, Kind: kind}
	l, err := netlink.LinkByName(name)
	if err != nil {
		return row
	}
	a := l.Attrs()
	row.LinkUp = a.Flags&net.FlagUp != 0
	row.MTU = a.MTU
	if s := a.Statistics; s != nil {
		row.RxBytes, row.TxBytes = s.RxBytes, s.TxBytes
		row.RxPkts, row.TxPkts = s.RxPackets, s.TxPackets
	}
	return row
}

func pickIfaceStats(all []ifaceJSON, selected string) *ifaceJSON {
	for i := range all {
		if all[i].Name == selected {
			return &all[i]
		}
	}
	return nil
}

func validPanelIface(selected string, tun Tunnel) bool {
	if selected == "" || selected == "all" {
		return true
	}
	for _, n := range tunnelMonitorDevs(tun) {
		if n == selected {
			return true
		}
	}
	if selected == "lo" {
		return true
	}
	return false
}

func fmtPanelURL(overlayPlain string, httpPort int) string {
	return fmt.Sprintf("http://%s:%d/", overlayPlain, httpPort)
}
