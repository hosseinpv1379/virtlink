// harness.go — tunnel lifecycle management.
//
// Supports three execution backends:
//   local  — spawn virlink processes directly on this host (needs root + netns or two IPs)
//   ssh    — start virlink on a remote peer via SSH, coordinate via its HTTP API
//   api    — assume virlink is already running; connect to its /health + /bench endpoints
package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"text/template"
	"time"
)

// ── Protocol descriptor ───────────────────────────────────────────────────────

// Proto describes one tunnel type in the test matrix.
type Proto struct {
	Name    string // e.g. "gre-fou"
	Label   string // display name
	NeedKernel bool // requires kernel module
	Port    int    // default UDP/TCP port
	// Extra tokens needed in the TOML (optional)
	Extras  map[string]string
}

// AllProtos is the complete protocol test matrix.
var AllProtos = []Proto{
	{Name: "gre-fou",        Label: "GRE-in-UDP (FOU)",       NeedKernel: true,  Port: 5556},
	{Name: "ipip-fou",       Label: "IPIP-in-UDP (FOU)",      NeedKernel: true,  Port: 5055},
	{Name: "bonded-gre-fou", Label: "Bonded GRE-FOU (2×BW)",  NeedKernel: true,  Port: 5557},
	{Name: "l2tpv3",         Label: "L2TPv3/UDP",             NeedKernel: true,  Port: 5059},
	{Name: "gre",            Label: "Raw GRE (proto 47)",     NeedKernel: true,  Port: 0},
	{Name: "udp-obfs",       Label: "UDP-Obfs AES-256-GCM",   NeedKernel: false, Port: 443},
	{Name: "tcp",            Label: "User-space TCP",         NeedKernel: false, Port: 8443},
	{Name: "udp",            Label: "User-space UDP",         NeedKernel: false, Port: 5060},
	{Name: "icmp",           Label: "ICMP Echo tunnel",       NeedKernel: false, Port: 0},
	{Name: "bip",            Label: "BIP (proto 58)",         NeedKernel: false, Port: 0},
}

// ── TOML template ─────────────────────────────────────────────────────────────

const configTmpl = `[tunnel]
type       = "{{.Type}}"
mode       = "{{.Mode}}"
local_ip   = "{{.LocalIP}}"
remote_ip  = "{{.RemoteIP}}"
cidr       = "{{.CIDR}}"
name       = "{{.IfName}}"

[transport]
port               = {{.Port}}
heartbeat_interval = {{.HeartbeatInterval}}

[logging]
level = "{{.LogLevel}}"

[health]
disabled = false
port     = {{.HealthPort}}

[tuning]
mss_clamp = true
bbr       = true
`

type configVars struct {
	Type              string
	Mode              string
	LocalIP           string
	RemoteIP          string
	CIDR              string
	IfName            string
	Port              int
	HeartbeatInterval int
	LogLevel          string
	HealthPort        int
}

// renderConfig produces a config.toml string.
func renderConfig(v configVars) (string, error) {
	tmpl, err := template.New("cfg").Parse(configTmpl)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, v); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// ── TunnelHandle ──────────────────────────────────────────────────────────────

// TunnelHandle controls one running virlink instance.
type TunnelHandle struct {
	Role       string // "A" or "B"
	OverlayIP  string // this side's overlay IP (e.g. "10.99.0.1")
	PeerOverIP string // peer's overlay IP
	HealthPort int
	BenchPort  int
	ConfigFile string
	LogFile    string

	// local process (backend == "local")
	proc *exec.Cmd

	// ssh session (backend == "ssh")
	sshConn *sshSession
}

func (h *TunnelHandle) Kill() {
	if h.proc != nil && h.proc.Process != nil {
		_ = h.proc.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { h.proc.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = h.proc.Process.Kill()
		}
	}
	if h.sshConn != nil {
		h.sshConn.Stop()
	}
}

// ── Local backend ─────────────────────────────────────────────────────────────

// LocalPair spawns two virlink processes on the local machine.
// localA and localB must be two distinct IPs bound on this host
// (e.g. 127.0.0.1 and 127.0.0.2, or two interface addresses).
func LocalPair(cfg *TestConfig, proto Proto, dir Direction, tmpDir string) (*TunnelHandle, *TunnelHandle, error) {
	// pick IPs and roles
	var aLocalIP, bLocalIP, aMode, bMode string
	if dir == DirAB {
		aLocalIP, bLocalIP = cfg.HostA.IP, cfg.HostB.IP
		aMode, bMode = "server", "client"
	} else {
		aLocalIP, bLocalIP = cfg.HostB.IP, cfg.HostA.IP
		aMode, bMode = "server", "client"
	}
	cidr := cfg.OverlayCIDR
	hp := cfg.HealthPort

	ifBase := fmt.Sprintf("vlt%s", proto.Name[:min(4, len(proto.Name))])
	ifA := ifBase + "a"
	ifB := ifBase + "b"

	// config for side-A
	cvA := configVars{
		Type: proto.Name, Mode: aMode,
		LocalIP: aLocalIP, RemoteIP: bLocalIP, CIDR: cidr,
		IfName: ifA, Port: proto.Port, HeartbeatInterval: 30,
		LogLevel: "info", HealthPort: hp,
	}
	// config for side-B
	cvB := configVars{
		Type: proto.Name, Mode: bMode,
		LocalIP: bLocalIP, RemoteIP: aLocalIP, CIDR: cidr,
		IfName: ifB, Port: proto.Port, HeartbeatInterval: 30,
		LogLevel: "info", HealthPort: hp,
	}

	tomlA, err := renderConfig(cvA)
	if err != nil {
		return nil, nil, err
	}
	tomlB, err := renderConfig(cvB)
	if err != nil {
		return nil, nil, err
	}

	fA := filepath.Join(tmpDir, fmt.Sprintf("%s-%s-A.toml", proto.Name, dir))
	fB := filepath.Join(tmpDir, fmt.Sprintf("%s-%s-B.toml", proto.Name, dir))
	if err := os.WriteFile(fA, []byte(tomlA), 0o600); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(fB, []byte(tomlB), 0o600); err != nil {
		return nil, nil, err
	}

	logA := strings.TrimSuffix(fA, ".toml") + ".log"
	logB := strings.TrimSuffix(fB, ".toml") + ".log"

	hA, err := spawnLocal(cfg.VirLinkBin, fA, logA)
	if err != nil {
		return nil, nil, fmt.Errorf("start A: %w", err)
	}
	hA.Role, hA.ConfigFile, hA.LogFile = "A", fA, logA
	hA.HealthPort, hA.BenchPort = hp, hp+1

	// derive overlay IPs from CIDR (server=.2, client=.1)
	hA.OverlayIP, hA.PeerOverIP = overlayIPs(cidr, aMode)

	// give server a moment before starting client
	time.Sleep(500 * time.Millisecond)

	hB, err := spawnLocal(cfg.VirLinkBin, fB, logB)
	if err != nil {
		hA.Kill()
		return nil, nil, fmt.Errorf("start B: %w", err)
	}
	hB.Role, hB.ConfigFile, hB.LogFile = "B", fB, logB
	hB.HealthPort, hB.BenchPort = hp, hp+1
	hB.OverlayIP, hB.PeerOverIP = overlayIPs(cidr, bMode)

	return hA, hB, nil
}

func spawnLocal(bin, cfgFile, logFile string) (*TunnelHandle, error) {
	lf, err := os.Create(logFile)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(bin, "-c", cfgFile)
	cmd.Stdout = lf
	cmd.Stderr = lf
	if err := cmd.Start(); err != nil {
		lf.Close()
		return nil, err
	}
	return &TunnelHandle{proc: cmd}, nil
}

// ── SSH backend ───────────────────────────────────────────────────────────────

// sshSession wraps a remote virlink process started via SSH.
type sshSession struct {
	cmd *exec.Cmd
}

// SSHPair starts virlink on the local machine (side A) and on a remote
// host (side B) via SSH.  The remote must have virlink at remoteBin.
func SSHPair(cfg *TestConfig, proto Proto, dir Direction, tmpDir string) (*TunnelHandle, *TunnelHandle, error) {
	hp := cfg.HealthPort

	var aMode, bMode string
	if dir == DirAB {
		aMode, bMode = "server", "client"
	} else {
		aMode, bMode = "client", "server"
	}

	// ── side A (local) ───────────────────────────────────────────────────────
	cvA := configVars{
		Type: proto.Name, Mode: aMode,
		LocalIP: cfg.HostA.IP, RemoteIP: cfg.HostB.IP, CIDR: cfg.OverlayCIDR,
		IfName: "vlt" + proto.Name[:min(4, len(proto.Name))],
		Port: proto.Port, HeartbeatInterval: 30,
		LogLevel: "info", HealthPort: hp,
	}
	tomlA, err := renderConfig(cvA)
	if err != nil {
		return nil, nil, err
	}
	fA := filepath.Join(tmpDir, fmt.Sprintf("%s-%s-A.toml", proto.Name, dir))
	if err := os.WriteFile(fA, []byte(tomlA), 0o600); err != nil {
		return nil, nil, err
	}
	logA := strings.TrimSuffix(fA, ".toml") + ".log"
	hA, err := spawnLocal(cfg.VirLinkBin, fA, logA)
	if err != nil {
		return nil, nil, fmt.Errorf("local side: %w", err)
	}
	hA.Role, hA.ConfigFile, hA.LogFile = "A", fA, logA
	hA.HealthPort, hA.BenchPort = hp, hp+1
	hA.OverlayIP, hA.PeerOverIP = overlayIPs(cfg.OverlayCIDR, aMode)

	// ── side B (remote via SSH) ───────────────────────────────────────────────
	cvB := configVars{
		Type: proto.Name, Mode: bMode,
		LocalIP: cfg.HostB.IP, RemoteIP: cfg.HostA.IP, CIDR: cfg.OverlayCIDR,
		IfName: "vlt" + proto.Name[:min(4, len(proto.Name))],
		Port: proto.Port, HeartbeatInterval: 30,
		LogLevel: "info", HealthPort: hp,
	}
	tomlB, err := renderConfig(cvB)
	if err != nil {
		hA.Kill()
		return nil, nil, err
	}

	// upload config to remote via stdin, then launch virlink
	hB, err := spawnSSH(cfg.HostB, tomlB, cfg.HostB.VirLinkBin, tmpDir, proto.Name, dir)
	if err != nil {
		hA.Kill()
		return nil, nil, fmt.Errorf("remote side: %w", err)
	}
	hB.Role, hB.HealthPort, hB.BenchPort = "B", hp, hp+1
	hB.OverlayIP, hB.PeerOverIP = overlayIPs(cfg.OverlayCIDR, bMode)

	return hA, hB, nil
}

func spawnSSH(host HostConfig, tomlContent, remoteBin, tmpDir, protoName string, dir Direction) (*TunnelHandle, error) {
	remoteCfg := fmt.Sprintf("/tmp/virlink-%s-%s-B.toml", protoName, dir)
	remoteLog := fmt.Sprintf("/tmp/virlink-%s-%s-B.log", protoName, dir)

	// 1. upload config via ssh+tee
	uploadCmd := exec.Command("ssh",
		sshArgs(host)...,
	)
	uploadArgs := append(sshArgs(host), "tee", remoteCfg)
	up := exec.Command("ssh", uploadArgs...)
	up.Stdin = strings.NewReader(tomlContent)
	if out, err := up.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("upload config: %s: %w", out, err)
	}

	// 2. start virlink remotely (nohup + background)
	startArgs := append(sshArgs(host),
		fmt.Sprintf("nohup %s -c %s >%s 2>&1 & echo $!", remoteBin, remoteCfg, remoteLog))
	startCmd := exec.Command("ssh", startArgs...)
	out, err := startCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("remote start: %s: %w", out, err)
	}
	_ = uploadCmd // silence unused warning

	sess := &sshSession{}
	_ = sess // will be used for Stop()

	return &TunnelHandle{sshConn: sess}, nil
}

func (s *sshSession) Stop() {
	// kill remote virlink (best effort)
	if s.cmd != nil {
		_ = s.cmd.Process.Signal(syscall.SIGTERM)
	}
}

// ── API-only backend ──────────────────────────────────────────────────────────

// APIHandle creates a TunnelHandle pointing at an already-running virlink.
func APIHandle(overlayIP, peerOverlayIP string, healthPort int) *TunnelHandle {
	return &TunnelHandle{
		OverlayIP:  overlayIP,
		PeerOverIP: peerOverlayIP,
		HealthPort: healthPort,
		BenchPort:  healthPort + 1,
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func sshArgs(h HostConfig) []string {
	args := []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "ConnectTimeout=10",
	}
	if h.SSHKey != "" {
		args = append(args, "-i", h.SSHKey)
	}
	if h.SSHPort != 0 {
		args = append(args, "-p", fmt.Sprintf("%d", h.SSHPort))
	}
	if h.SSHUser != "" {
		args = append(args, h.SSHUser+"@"+h.IP)
	} else {
		args = append(args, h.IP)
	}
	return args
}

// overlayIPs derives the /32 overlay address for this side from the CIDR.
// server gets .2, client gets .1
func overlayIPs(cidr, mode string) (myIP, peerIP string) {
	// parse base: "10.99.0.0/30" → base = "10.99.0."
	parts := strings.SplitN(cidr, "/", 2)
	base := parts[0]
	octets := strings.Split(base, ".")
	if len(octets) != 4 {
		return "0.0.0.0", "0.0.0.0"
	}
	prefix := strings.Join(octets[:3], ".") + "."
	if mode == "client" {
		return prefix + "1", prefix + "2"
	}
	return prefix + "2", prefix + "1"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
