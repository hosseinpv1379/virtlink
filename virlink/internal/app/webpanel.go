package app

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"virlink/internal/platform"
	"virlink/internal/webpanel"
)

func runWebPanel(cfgPath string) int {
	cfg, err := webpanel.LoadConfig(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, platform.Color(platform.CRed, "✗")+" "+err.Error())
		return 1
	}

	platform.InitLogger(nil)
	platform.LogInfo("virlink web panel starting")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		platform.LogInfo("web panel shutting down")
		cancel()
	}()

	if err := webpanel.Run(ctx, cfg); err != nil {
		platform.LogError("web panel: " + err.Error())
		return 1
	}
	return 0
}

func hashPasswordCLI(user, password string) {
	if password == "" {
		fmt.Fprintln(os.Stderr, "password required (pipe or argument)")
		os.Exit(1)
	}
	if user == "" {
		user = "admin"
	}
	fmt.Println(webpanel.HashPassword(password, user))
}
