// cli.go — CLI entry (called from cmd/virlink).
package virlink

import (
	"flag"
	"fmt"
	"os"
)

const version = "2.10.16"

func Main() {
	cfgFile  := flag.String("c", "", "path to config.toml")
	doDown   := flag.Bool("down", false, "tear down tunnel (one-shot)")
	doStatus := flag.Bool("status", false, "show current tunnel status")
	doVer    := flag.Bool("version", false, "print version")
	flag.Usage = printUsage
	flag.Parse()

	if *doVer {
		fmt.Printf("virlink v%s\n", version)
		return
	}

	if *cfgFile == "" {
		printUsage()
		os.Exit(1)
	}

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, color(cRed, "✗")+" must run as root (sudo ./virlink ...)")
		os.Exit(1)
	}

	cfg, err := loadConfig(*cfgFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, color(cRed, "✗")+" config: "+err.Error())
		os.Exit(1)
	}

	tun, err := newTunnel(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, color(cRed, "✗")+" "+err.Error())
		os.Exit(1)
	}

	switch {
	case *doStatus:
		// one-shot status print
		tun.Status()

	case *doDown:
		// one-shot teardown
		initLogger(&cfg.Logging)
		logInfo("tearing down tunnel...")
		if err := tun.Down(); err != nil {
			logError("teardown: " + err.Error())
			os.Exit(1)
		}
		logInfo("done")

	default:
		// ── daemon mode ─────────────────────────────────────────────────────
		// The tunnel lives as long as this process runs.
		// Press Ctrl+C (or send SIGTERM) to cleanly remove the tunnel.
		os.Exit(runDaemon(cfg, tun))
	}
}

func printUsage() {
	fmt.Printf(`
virlink v%s — kernel tunnel manager

Usage:
  sudo ./virlink -c config.toml            run (tunnel up, blocks, Ctrl+C removes)
  sudo ./virlink -c config.toml --down     tear down tunnel
  sudo ./virlink -c config.toml --status   show tunnel status
       ./virlink --version

Tunnel types  ([tunnel] type = "..." in config.toml):
  gre-fou         GRE in UDP (FOU)           port 5556
  ipip-fou        IPIP in UDP (FOU)          port 5055
  bonded-gre-fou  dual GRE-FOU ECMP 2×BW    port 5557/5558
  l2tpv3          L2TPv3 over UDP            port 5059
  gre-fou-ipsec   GRE-FOU + IPsec ESP        port 5556
  udp-obfs        AES-256-GCM obfuscated UDP port 443
  gre             Kernel GRE (proto 47)      raw
  tcp             User-space TCP tunnel      port 8443
  openvpn         OpenVPN (openvpn core)     port 1194
  udp             User-space UDP tunnel      port 5060
  icmp            ICMP Echo tunnel (proto 1) raw
  bip             BIP tunnel (proto 58)      raw

Lifecycle:
  • tunnel is created when the process starts
  • heartbeat log printed every [transport] heartbeat_interval seconds
  • Ctrl+C / SIGTERM → tunnel removed automatically

Examples:
  sudo ./virlink -c configs/examples/gre-fou/client/config.toml

`, version)
}
