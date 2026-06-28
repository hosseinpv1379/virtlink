// Package virlink implements the Linux tunnel manager core.
//
// Repository layout:
//
//	cmd/virlink/          CLI entry point (thin wrapper)
//	internal/virlink/     all tunnel and runtime logic
//	configs/examples/     sample config.toml per tunnel type
//	configs/spooftest/    manual wire-spoof test configs
//	scripts/setup.sh      interactive installer / manager
//	scripts/release.sh    publish binary + setup.sh to GitHub
//	test/                 integration test harness (separate module)
//
// Source file map (internal/virlink/):
//
//	Entry & lifecycle
//	  cli.go        CLI flags, usage, Main()
//	  daemon.go     long-running process (Up → heartbeat → Down on signal)
//	  config.go     TOML config load/validate
//	  tunnel.go     Tunnel interface + factory
//
//	Core infrastructure
//	  netops.go     netlink link/addr/route operations
//	  runner.go     subprocess helpers (modprobe, ip, wg, iptables)
//	  setup.go      module load, bonding, MSS clamp
//	  logger.go     logging, banner, terminal UI
//	  health.go     UDP probe + HTTP /health + dashboard data
//	  forward.go    iptables port forwarding (client mode)
//	  tuning.go     scoped server sysctl tuning
//
//	Performance & diagnostics
//	  perf.go       [tuning] runtime knobs (queues, batch, poll)
//	  pool.go       buffer pools, raw socket helpers, dedup
//	  stats.go      lock-free activity counters + /profile
//	  bench.go      in-tunnel bandwidth test server
//	  ui.go         HTML dashboard (GET /)
//
//	Wire spoofing (userspace + kernel)
//	  spoof.go          [mangle] srcip/dstip validation
//	  wire_ip.go        IPv4 header build/parse for raw sockets
//	  mangle_kernel.go  nftables wire spoof for kernel tunnels
//
//	Userspace tunnel I/O
//	  tundev.go     TUN device (single + multi-queue)
//	  tun_poll.go   shared TUN TX poll loop
//	  batch_linux.go  sendmmsg batching (linux/amd64)
//
//	Kernel tunnels (netlink)
//	  tun_gre_fou.go  tun_ipip_fou.go  tun_bonded.go  tun_l2tpv3.go
//	  tun_ipsec.go   tun_gre.go
//
//	Userspace tunnels (TUN + raw/UDP/TCP/OpenVPN)
//	  tun_icmp.go  tun_udp.go  tun_tcp.go  tun_bip.go  tun_udp_obfs.go  tun_openvpn.go  tun_hysteria2.go
package virlink
