// tuning.go — scoped server tuning for active virlink tunnels.
//
// Nothing is written to /etc/sysctl.conf or /etc/profile. Parameters are applied
// via /proc/sys when a tunnel comes up and restored to their previous values
// when the tunnel is torn down. Per-interface settings target only the tunnel
// device(s); global socket/TCP knobs are adjusted temporarily to help traffic
// through the overlay and reverted on teardown.
package platform

import (
	"virlink/internal/config"
	"fmt"
	"strings"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	tuningBalanced = "balanced"
	tuningFast     = "fast"
	tuningResource = "resource"
	tuningLatency  = "latency"
)

var (
	tuningMu     sync.Mutex
	activeTuning *tunnelTuning
	tuningRefs   int // active tunnel count — restore sysctl only when last tunnel stops
)

type sysctlParam struct{ k, v string }

type tuningProfile struct {
	global   []sysctlParam
	txQLen   int
	qdisc    string
	nofile   uint64
}

type SavedSysctl struct {
	Key string
	Val string
	Ok  bool
}

type savedLink struct {
	dev    string
	txQLen int
	ok     bool
}

type tunnelTuning struct {
	cfg        *config.Config
	devs       []string
	saved      []SavedSysctl
	savedLinks []savedLink
	savedNOFile unix.Rlimit
	hadNOFile   bool
}

func tuningEnabled(cfg *config.Config) bool {
	if cfg.Tuning.Enabled != nil {
		return *cfg.Tuning.Enabled
	}
	return true
}

func tuningMode(cfg *config.Config) string {
	m := strings.ToLower(strings.TrimSpace(cfg.Tuning.Mode))
	if m == "" {
		return tuningBalanced
	}
	return m
}

func TuningModeLabel(cfg *config.Config) string {
	if !tuningEnabled(cfg) {
		return "off"
	}
	return tuningMode(cfg)
}

func validateTuningMode(mode string) error {
	switch mode {
	case tuningBalanced, tuningFast, tuningResource, tuningLatency:
		return nil
	default:
		return fmt.Errorf("[tuning] mode must be %q, %q, %q, or %q, got %q",
			tuningBalanced, tuningFast, tuningResource, tuningLatency, mode)
	}
}

func profileForMode(mode string) tuningProfile {
	switch mode {
	case tuningFast:
		return tuningProfile{
			global: fastGlobalParams(),
			txQLen: 10000,
			qdisc:  "fq",
			nofile: 1_048_576,
		}
	case tuningResource:
		return tuningProfile{
			global: resourceGlobalParams(),
			txQLen: 2000,
			qdisc:  "",
			nofile: 32_768,
		}
	case tuningLatency:
		return tuningProfile{
			global: latencyGlobalParams(),
			txQLen: 5000,
			qdisc:  "fq_codel",
			nofile: 65_536,
		}
	default: // balanced
		return tuningProfile{
			global: balancedGlobalParams(),
			txQLen: 10000,
			qdisc:  "fq",
			nofile: 65_536,
		}
	}
}

// requiredGlobalParams — minimum for overlay forwarding (always applied).
func requiredGlobalParams() []sysctlParam {
	return []sysctlParam{
		{"net.ipv4.ip_forward", "1"},
		{"net.ipv6.conf.all.forwarding", "1"},
	}
}

func balancedGlobalParams() []sysctlParam {
	return append(requiredGlobalParams(), []sysctlParam{
		{"net.core.default_qdisc", "fq"},
		{"net.ipv4.tcp_congestion_control", "bbr"},
		// 64 MB matches perfSockBuf() for tcp/tcpmux so SO_RCVBUF requests succeed
		// without needing SO_RCVBUFFORCE (though tuneTCPConnForce tries that too).
		{"net.core.rmem_max", "67108864"},
		{"net.core.wmem_max", "67108864"},
		{"net.core.rmem_default", "1048576"},
		{"net.core.wmem_default", "1048576"},
		{"net.ipv4.tcp_rmem", "16384 1048576 67108864"},
		{"net.ipv4.tcp_wmem", "16384 1048576 67108864"},
		{"net.ipv4.tcp_mtu_probing", "1"},
		{"net.core.netdev_max_backlog", "32768"},
		{"net.core.optmem_max", "262144"},
		{"net.ipv4.udp_rmem_min", "65536"},
		{"net.ipv4.udp_wmem_min", "65536"},
		{"net.ipv4.udp_mem", "65536 1048576 67108864"},
		{"net.ipv4.tcp_slow_start_after_idle", "0"},
		{"net.ipv4.tcp_sack", "1"},
		{"net.ipv4.tcp_window_scaling", "1"},
	}...)
}

func fastGlobalParams() []sysctlParam {
	return append(requiredGlobalParams(), []sysctlParam{
		{"net.core.default_qdisc", "fq"},
		{"net.core.netdev_max_backlog", "32768"},
		{"net.core.optmem_max", "262144"},
		{"net.core.somaxconn", "65536"},
		{"net.core.rmem_max", "67108864"},
		{"net.core.rmem_default", "1048576"},
		{"net.core.wmem_max", "67108864"},
		{"net.core.wmem_default", "1048576"},
		{"net.ipv4.tcp_rmem", "16384 1048576 67108864"},
		{"net.ipv4.tcp_wmem", "16384 1048576 67108864"},
		{"net.ipv4.tcp_congestion_control", "bbr"},
		{"net.ipv4.tcp_fin_timeout", "25"},
		{"net.ipv4.tcp_keepalive_time", "1200"},
		{"net.ipv4.tcp_keepalive_probes", "7"},
		{"net.ipv4.tcp_keepalive_intvl", "30"},
		{"net.ipv4.tcp_max_orphans", "819200"},
		{"net.ipv4.tcp_max_syn_backlog", "20480"},
		{"net.ipv4.tcp_max_tw_buckets", "1440000"},
		{"net.ipv4.tcp_mem", "65536 1048576 33554432"},
		{"net.ipv4.tcp_mtu_probing", "1"},
		{"net.ipv4.tcp_notsent_lowat", "32768"},
		{"net.ipv4.tcp_retries2", "8"},
		{"net.ipv4.tcp_sack", "1"},
		{"net.ipv4.tcp_dsack", "1"},
		{"net.ipv4.tcp_slow_start_after_idle", "0"},
		{"net.ipv4.tcp_window_scaling", "1"},
		{"net.ipv4.tcp_adv_win_scale", "-2"},
		{"net.ipv4.tcp_ecn", "1"},
		{"net.ipv4.tcp_ecn_fallback", "1"},
		{"net.ipv4.tcp_syncookies", "1"},
		{"net.ipv4.udp_mem", "65536 1048576 33554432"},
		{"net.unix.max_dgram_qlen", "256"},
	}...)
}

func resourceGlobalParams() []sysctlParam {
	return append(requiredGlobalParams(), []sysctlParam{
		{"net.core.rmem_max", "4194304"},
		{"net.core.wmem_max", "4194304"},
		{"net.core.rmem_default", "262144"},
		{"net.core.wmem_default", "262144"},
		{"net.ipv4.tcp_rmem", "4096 87380 4194304"},
		{"net.ipv4.tcp_wmem", "4096 65536 4194304"},
		{"net.ipv4.tcp_congestion_control", "cubic"},
		{"net.core.netdev_max_backlog", "16384"},
		{"net.ipv4.udp_rmem_min", "16384"},
		{"net.ipv4.udp_wmem_min", "16384"},
		{"net.ipv4.udp_mem", "16384 262144 4194304"},
		{"net.ipv4.tcp_mem", "16384 262144 4194304"},
	}...)
}

func latencyGlobalParams() []sysctlParam {
	return append(requiredGlobalParams(), []sysctlParam{
		{"net.core.default_qdisc", "fq_codel"},
		{"net.ipv4.tcp_congestion_control", "bbr"},
		{"net.core.rmem_max", "16777216"},
		{"net.core.wmem_max", "16777216"},
		{"net.core.rmem_default", "524288"},
		{"net.core.wmem_default", "524288"},
		{"net.ipv4.tcp_rmem", "4096 524288 16777216"},
		{"net.ipv4.tcp_wmem", "4096 524288 16777216"},
		{"net.ipv4.tcp_fin_timeout", "25"},
		{"net.ipv4.tcp_slow_start_after_idle", "0"},
		{"net.ipv4.tcp_notsent_lowat", "32768"},
		{"net.ipv4.tcp_mtu_probing", "1"},
		{"net.core.netdev_max_backlog", "16384"},
		{"net.ipv4.tcp_sack", "1"},
		{"net.ipv4.tcp_window_scaling", "1"},
	}...)
}

func perDevParams(dev string) []sysctlParam {
	return []sysctlParam{
		{"net.ipv4.conf." + dev + ".rp_filter", "2"},
		{"net.ipv4.conf." + dev + ".accept_source_route", "0"},
	}
}

// clearICMPEchoIgnoreAll drops icmp_echo_ignore_all if something else enabled it.
// Not saved/restored — we never want overlay ping broken while virlink runs.
func clearICMPEchoIgnoreAll() {
	key := "net.ipv4.icmp_echo_ignore_all"
	val, err := readSysctl(key)
	if err != nil || val != "1" {
		return
	}
	if err := nlSysctl(key, "0"); err != nil {
		warn("tuning " + key + ": " + err.Error())
		return
	}
	logOK("cleared " + key + " (was blocking overlay ICMP echo replies)")
}

func ApplyTunnelTuning(cfg *config.Config, devs ...string) {
	applyPerfFromConfig(cfg)

	tuningMu.Lock()
	defer tuningMu.Unlock()

	tuningRefs++
	if activeTuning != nil {
		activeTuning.mergeDevs(cfg, devs...)
		if tuningEnabled(cfg) {
			logOK(fmt.Sprintf("tuning merged: +devs=%v (refs=%d)", devs, tuningRefs))
		}
		return
	}

	tt := &tunnelTuning{cfg: cfg, devs: append([]string(nil), devs...)}
	tt.applyLocked()
	activeTuning = tt

	if tuningEnabled(cfg) {
		logOK(fmt.Sprintf("tuning applied: mode=%s devs=%v (restored on teardown)", tuningMode(cfg), devs))
	} else {
		logOK("tuning disabled — only forwarding + per-device filters applied")
	}
}

func RestoreTunnelTuning() {
	tuningMu.Lock()
	defer tuningMu.Unlock()
	if tuningRefs > 0 {
		tuningRefs--
	}
	if tuningRefs > 0 {
		return // other tunnels still up — keep sysctl
	}
	if activeTuning != nil {
		activeTuning.restoreLocked()
		activeTuning = nil
	}
}

func (tt *tunnelTuning) set(key, val string) {
	prev, err := readSysctl(key)
	entry := SavedSysctl{Key: key, Ok: err == nil}
	if entry.Ok {
		entry.Val = prev
	}
	tt.saved = append(tt.saved, entry)
	if err := nlSysctl(key, val); err != nil {
		warn(fmt.Sprintf("tuning %s: %v", key, err))
	}
}

func (tt *tunnelTuning) applyLocked() {
	cfg := tt.cfg

	var params []sysctlParam
	if tuningEnabled(cfg) {
		p := profileForMode(tuningMode(cfg))
		params = append(params, p.global...)
		for _, dev := range tt.devs {
			params = append(params, perDevParams(dev)...)
		}
		if cfg.Tuning.Multipath {
			params = append(params, sysctlParam{"net.ipv4.fib_multipath_hash_policy", "1"})
		}
		tt.applyLinkProfile(p)
		tt.applyProcessLimits(p.nofile)
	} else {
		params = append(requiredGlobalParams(), []sysctlParam{
			// Minimum headroom so tuneTCPConnForce / tuneUDPConn can use large buffers.
			{"net.core.rmem_max", "67108864"},
			{"net.core.wmem_max", "67108864"},
			{"net.ipv4.udp_rmem_min", "65536"},
			{"net.ipv4.udp_wmem_min", "65536"},
		}...)
		for _, dev := range tt.devs {
			params = append(params, perDevParams(dev)...)
		}
		if cfg.Tuning.Multipath {
			params = append(params, sysctlParam{"net.ipv4.fib_multipath_hash_policy", "1"})
		}
	}

	// Do NOT set net.ipv4.icmp_echo_ignore_all — global, breaks overlay ping on all
	// tunnels. Duplicate wire ICMP is filtered in userspace (protocol/icmp rxLoop).
	clearICMPEchoIgnoreAll()

	for _, p := range params {
		tt.set(p.k, p.v)
	}
}

func (tt *tunnelTuning) mergeDevs(cfg *config.Config, devs ...string) {
	for _, dev := range devs {
		if dev == "" || tuningHasDev(tt.devs, dev) {
			continue
		}
		tt.devs = append(tt.devs, dev)
		for _, p := range perDevParams(dev) {
			tt.set(p.k, p.v)
		}
		if tuningEnabled(cfg) {
			tt.applyLinkProfileDev(dev, profileForMode(tuningMode(cfg)))
		}
	}
}

func tuningHasDev(devs []string, dev string) bool {
	for _, d := range devs {
		if d == dev {
			return true
		}
	}
	return false
}

func (tt *tunnelTuning) applyLinkProfile(p tuningProfile) {
	for _, dev := range tt.devs {
		tt.applyLinkProfileDev(dev, p)
	}
}

func (tt *tunnelTuning) applyLinkProfileDev(dev string, p tuningProfile) {
	link, err := netlink.LinkByName(dev)
	if err != nil {
		warn("tuning link " + dev + ": " + err.Error())
		return
	}
	sl := savedLink{dev: dev, ok: true, txQLen: link.Attrs().TxQLen}
	tt.savedLinks = append(tt.savedLinks, sl)

	if qlen := perfTxQLen(); qlen > 0 {
		_ = netlink.LinkSetTxQLen(link, qlen)
	}
	if p.qdisc != "" && link.Type() != "tun" {
		if err := replaceDevQdisc(link, p.qdisc); err != nil {
			warn(fmt.Sprintf("tuning qdisc %s on %s: %v", p.qdisc, dev, err))
		}
	}
}

func replaceDevQdisc(link netlink.Link, kind string) error {
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(1, 0),
			Parent:    netlink.HANDLE_ROOT,
		},
		QdiscType: kind,
	}
	return netlink.QdiscReplace(qdisc)
}

func restoreDevQdisc(link netlink.Link) {
	_ = netlink.QdiscReplace(&netlink.PfifoFast{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(1, 0),
			Parent:    netlink.HANDLE_ROOT,
		},
	})
}

func (tt *tunnelTuning) applyProcessLimits(nofile uint64) {
	if nofile == 0 {
		return
	}
	var old unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &old); err == nil {
		tt.savedNOFile = old
		tt.hadNOFile = true
	}
	newLim := unix.Rlimit{Cur: nofile, Max: nofile}
	if old := tt.savedNOFile; tt.hadNOFile && old.Max > 0 && old.Max < nofile {
		newLim.Max = old.Max
		if newLim.Cur > newLim.Max {
			newLim.Cur = newLim.Max
		}
	}
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &newLim); err != nil {
		warn("tuning ulimit nofile: " + err.Error())
	}
}

func (tt *tunnelTuning) restoreLocked() {
	for i := len(tt.saved) - 1; i >= 0; i-- {
		e := tt.saved[i]
		if !e.Ok {
			continue
		}
		_ = nlSysctl(e.Key, e.Val)
	}
	for _, sl := range tt.savedLinks {
		link, err := netlink.LinkByName(sl.dev)
		if err != nil {
			continue
		}
		if sl.ok && sl.txQLen > 0 {
			_ = netlink.LinkSetTxQLen(link, sl.txQLen)
		}
		if link.Type() != "tun" {
			restoreDevQdisc(link)
		}
	}
	if tt.hadNOFile {
		_ = unix.Setrlimit(unix.RLIMIT_NOFILE, &tt.savedNOFile)
	}
}
