package webpanel

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"virlink/internal/config"
	"virlink/internal/core"
	"virlink/internal/platform"
)

// TunnelRow is one tunnel shown in the dashboard.
type TunnelRow struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Mode        string `json:"mode"`
	Service     string `json:"service"`     // running | stopped | failed
	Handshake   string `json:"handshake"`   // connected | waiting | degraded | dead | n/a
	LinkUp      bool   `json:"link_up"`
	OverlayIP   string `json:"overlay_ip"`
	PeerIP      string `json:"peer_ip"`
	RemoteIP    string `json:"remote_ip"`
	LocalIP     string `json:"local_ip"`
	PanelURL    string `json:"panel_url"`
	HealthError string `json:"health_error,omitempty"`
	Uptime      string `json:"uptime,omitempty"`
}

func DiscoverTunnels(configsDir string) ([]TunnelRow, error) {
	entries, err := os.ReadDir(configsDir)
	if err != nil {
		return nil, err
	}
	var rows []TunnelRow
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".toml") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".toml")
		cfgPath := filepath.Join(configsDir, e.Name())
		row, err := discoverOne(name, cfgPath)
		if err != nil {
			row = TunnelRow{Name: name, Service: "error", HealthError: err.Error()}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func discoverOne(name, cfgPath string) (TunnelRow, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return TunnelRow{}, err
	}
	platform.FinalizeConfig(cfg)
	if cfg.Tunnel.Name == "" {
		cfg.Tunnel.Name = name
	}

	row := TunnelRow{
		Name:      name,
		Type:      cfg.Tunnel.Type,
		Mode:      cfg.Tunnel.Mode,
		LocalIP:   cfg.Tunnel.LocalIP,
		RemoteIP:  cfg.Tunnel.RemoteIP,
		OverlayIP: core.PlainIP(core.OverlayAddr(cfg, "")),
		PeerIP:    core.PeerAddr(cfg, ""),
		Service:   serviceState(name),
	}

	if cfg.Health.Disabled {
		row.Handshake = "n/a"
		row.PanelURL = ""
		return row, nil
	}

	httpPort := cfg.Health.HTTPPort
	if httpPort == 0 {
		httpPort = 6543
	}
	row.PanelURL = fmt.Sprintf("http://%s:%d/", row.OverlayIP, httpPort)

	if row.Service != "running" {
		row.Handshake = "stopped"
		return row, nil
	}

	hs, linkUp, uptime, herr := fetchHealth(row.OverlayIP, httpPort)
	row.Handshake = hs
	row.LinkUp = linkUp
	row.Uptime = uptime
	row.HealthError = herr
	return row, nil
}

func serviceState(name string) string {
	out, err := exec.Command("systemctl", "is-active", "virlink-"+name).CombinedOutput()
	s := strings.TrimSpace(string(out))
	switch s {
	case "active":
		return "running"
	case "inactive":
		return "stopped"
	case "failed":
		return "failed"
	default:
		if err != nil {
			return "stopped"
		}
		return s
	}
}

type healthResp struct {
	Handshake string `json:"handshake"`
	Uptime    string `json:"uptime"`
	Interface string `json:"interface"`
	Status    string `json:"status"`
}

func fetchHealth(overlayIP string, httpPort int) (handshake string, linkUp bool, uptime, errMsg string) {
	url := fmt.Sprintf("http://%s:%d/health", overlayIP, httpPort)
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "unknown", false, "", err.Error()
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "unknown", false, "", err.Error()
	}
	var hr healthResp
	if err := json.Unmarshal(body, &hr); err != nil {
		return "unknown", false, "", "invalid health JSON"
	}
	hs := hr.Handshake
	if hs == "" {
		hs = "unknown"
	}
	// Link considered up when we got a JSON response from overlay.
	linkUp = net.ParseIP(overlayIP) != nil && resp.StatusCode < 500
	return hs, linkUp, hr.Uptime, ""
}
