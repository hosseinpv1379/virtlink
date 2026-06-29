package webpanel

import (
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"virlink/internal/config"
	"virlink/internal/core"
	"virlink/internal/platform"
)

type tunnelEndpoint struct {
	Name      string
	OverlayIP string
	HTTPPort  int
	Disabled  bool
}

func resolveTunnel(configsDir, name string) (*tunnelEndpoint, error) {
	if name == "" || strings.Contains(name, "/") || strings.Contains(name, "..") {
		return nil, fmt.Errorf("invalid tunnel name")
	}
	cfgPath := filepath.Join(configsDir, name+".toml")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}
	platform.FinalizeConfig(cfg)
	ep := &tunnelEndpoint{
		Name:      name,
		OverlayIP: core.PlainIP(core.OverlayAddr(cfg, "")),
		HTTPPort:  cfg.Health.HTTPPort,
		Disabled:  cfg.Health.Disabled,
	}
	if ep.HTTPPort == 0 {
		ep.HTTPPort = 6543
	}
	return ep, nil
}

func proxyTunnelGET(overlayIP string, httpPort int, path string, timeout time.Duration) ([]byte, int, error) {
	url := fmt.Sprintf("http://%s:%d%s", overlayIP, httpPort, path)
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

func parseTunnelAPIPath(path string) (name, action string, ok bool) {
	path = strings.TrimPrefix(path, "/api/tunnel/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}
