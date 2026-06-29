package webpanel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"virlink/internal/platform"
)

// Run starts the centralized web panel HTTP server (blocks until ctx cancelled).
func Run(ctx context.Context, cfg *Config) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(dashboardHTML))
	})

	mux.HandleFunc("/api/tunnels", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		rows, err := DiscoverTunnels(cfg.ConfigsDir)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tunnels": rows,
			"count":   len(rows),
		})
	})

	mux.HandleFunc("/api/tunnel/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name, action, ok := parseTunnelAPIPath(r.URL.Path)
		if !ok {
			http.NotFound(w, r)
			return
		}
		ep, err := resolveTunnel(cfg.ConfigsDir, name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		if ep.Disabled {
			http.Error(w, "health disabled for this tunnel", http.StatusBadRequest)
			return
		}
		if serviceState(name) != "running" {
			http.Error(w, "tunnel service not running", http.StatusServiceUnavailable)
			return
		}

		var path string
		var timeout time.Duration
		switch action {
		case "health":
			path = "/health"
			if q := r.URL.RawQuery; q != "" {
				path += "?" + q
			}
			timeout = 5 * time.Second
		case "bench":
			path = "/bench"
			if q := r.URL.RawQuery; q != "" {
				path += "?" + q
			}
			timeout = 120 * time.Second
		default:
			http.NotFound(w, r)
			return
		}

		body, code, err := proxyTunnelGET(ep.OverlayIP, ep.HTTPPort, path, timeout)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": fmt.Sprintf("tunnel %s unreachable: %v", name, err),
			})
			return
		}
		ct := "application/json"
		if strings.HasPrefix(action, "bench") || strings.Contains(string(body), "{") {
			w.Header().Set("Content-Type", ct)
		}
		w.WriteHeader(code)
		_, _ = w.Write(body)
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "service": "virlink-webpanel"})
	})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != cfg.Username || !verifyPassword(pass, cfg.PasswordHash, cfg.Username) {
			authFailed(w)
			return
		}
		mux.ServeHTTP(w, r)
	})

	srv := &http.Server{
		Addr:         cfg.Listen,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 130 * time.Second,
	}

	platform.LogInfo(fmt.Sprintf("web panel listening on http://%s/  (auth required, all-in-one)", cfg.Listen))

	go func() {
		<-ctx.Done()
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shCtx)
	}()

	err := srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
