// cli.go — CLI entry (called from cmd/virlink).
package app

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	_ "virlink/internal/protocol"
	"virlink/internal/config"
	"virlink/internal/core"
	"virlink/internal/platform"
)

const version = "3.3.14"

func Main() {
	cfgFile := flag.String("c", "", "path to config.toml (tunnel or web panel)")
	doDown := flag.Bool("down", false, "tear down tunnel (one-shot)")
	doStatus := flag.Bool("status", false, "show current tunnel status")
	doVer := flag.Bool("version", false, "print version")
	doVerbose := flag.Bool("v", false, "verbose debug logging (log every command)")
	doWeb := flag.Bool("web", false, "run centralized web panel service")
	doHashPW := flag.Bool("hash-password", false, "print web panel password hash (pass password as arg or stdin)")
	hashUser := flag.String("user", "admin", "username for --hash-password salt")
	flag.BoolVar(doVerbose, "verbose", false, "verbose debug logging (log every command)")
	flag.Usage = printUsage
	flag.Parse()

	if *doVer {
		fmt.Printf("virlink v%s\n", version)
		return
	}

	if *doHashPW {
		pass := strings.TrimSpace(strings.Join(flag.Args(), " "))
		if pass == "" {
			sc := bufio.NewScanner(os.Stdin)
			if sc.Scan() {
				pass = strings.TrimSpace(sc.Text())
			}
		}
		hashPasswordCLI(*hashUser, pass)
		return
	}

	if *doWeb {
		if os.Geteuid() != 0 {
			fmt.Fprintln(os.Stderr, platform.Color(platform.CRed, "✗")+" web panel must run as root (sudo)")
			os.Exit(1)
		}
		path := *cfgFile
		if path == "" {
			path = "/opt/virlink/webpanel.toml"
		}
		os.Exit(runWebPanel(path))
	}

	if *cfgFile == "" {
		printUsage()
		os.Exit(1)
	}

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, platform.Color(platform.CRed, "✗")+" must run as root (sudo ./virlink ...)")
		os.Exit(1)
	}

	cfg, err := config.Load(*cfgFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, platform.Color(platform.CRed, "✗")+" config: "+err.Error())
		os.Exit(1)
	}
	platform.FinalizeConfig(cfg)
	if err := platform.ValidateConfig(cfg); err != nil {
		fmt.Fprintln(os.Stderr, platform.Color(platform.CRed, "✗")+" config: "+err.Error())
		os.Exit(1)
	}

	tun, err := core.New(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, platform.Color(platform.CRed, "✗")+" "+err.Error())
		os.Exit(1)
	}

	switch {
	case *doStatus:
		tun.Status()

	case *doDown:
		if *doVerbose {
			cfg.Logging.Level = "debug"
		}
		platform.InitLogger(&cfg.Logging)
		platform.LogInfo("tearing down tunnel...")
		if err := tun.Down(); err != nil {
			platform.LogError("teardown: " + err.Error())
			os.Exit(1)
		}
		platform.LogInfo("done")

	default:
		if *doVerbose {
			cfg.Logging.Level = "debug"
		}
		os.Exit(runDaemon(cfg, tun))
	}
}

func printUsage() {
	fmt.Printf(`
virlink v%s — kernel tunnel manager

Usage:
  sudo ./virlink -c config.toml            run tunnel (blocks until Ctrl+C)
  sudo ./virlink --web -c webpanel.toml    run centralized web panel
  ./virlink --hash-password SECRET           hash password for web panel config
  sudo ./virlink -c config.toml --down     tear down tunnel
  sudo ./virlink -c config.toml --status   show tunnel status
       ./virlink --version

Web panel:
  Install via virlink-setup → Install Web Panel
  Scans /opt/virlink/configs/*.toml and shows all tunnels (HTTP Basic Auth)

Tunnel lifecycle:
  • Link state is logged only on change (connected / waiting / disconnected)
  • Ctrl+C / SIGTERM → tunnel removed automatically

Examples:
  sudo ./virlink -c /opt/virlink/configs/mylink.toml
  sudo ./virlink --web -c /opt/virlink/webpanel.toml

`, version)
}
