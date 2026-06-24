// forward.go — iptables port forwarding rules.
// Only applied when mode = "client" and [forward] enabled = true.
//
// Rule format: "listenPort:targetPort"
//   "1000:2000" → traffic arriving on :1000 is DNAT'd to peerIP:2000
//   Works for both TCP and UDP.
package main

import (
	"fmt"
	"strconv"
	"strings"
)

// ForwardRule is one listen→target port mapping.
type ForwardRule struct {
	ListenPort int
	TargetPort int
	Proto      string // "tcp" | "udp" | "both" (default)
}

// parseRules parses config strings like "1000:2000" or "1000:2000/tcp".
func parseRules(raw []string) ([]ForwardRule, error) {
	var out []ForwardRule
	for _, s := range raw {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}

		proto := "both"
		if idx := strings.LastIndex(s, "/"); idx > 0 {
			proto = strings.ToLower(s[idx+1:])
			s = s[:idx]
			if proto != "tcp" && proto != "udp" {
				return nil, fmt.Errorf("rule %q: proto must be tcp or udp", s)
			}
		}

		parts := strings.SplitN(s, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("rule %q: must be listenPort:targetPort", s)
		}
		lp, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil || lp < 1 || lp > 65535 {
			return nil, fmt.Errorf("rule %q: invalid listen port", s)
		}
		tp, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil || tp < 1 || tp > 65535 {
			return nil, fmt.Errorf("rule %q: invalid target port", s)
		}
		out = append(out, ForwardRule{ListenPort: lp, TargetPort: tp, Proto: proto})
	}
	return out, nil
}

// ApplyForward installs DNAT + MASQUERADE rules.
// peerIP is the overlay IP of the server (e.g. "10.20.10.2").
func ApplyForward(peerIP string, rules []ForwardRule) {
	if len(rules) == 0 {
		return
	}
	logInfo(fmt.Sprintf("port forward → peer %s", peerIP))

	for _, r := range rules {
		target := fmt.Sprintf("%s:%d", peerIP, r.TargetPort)
		protos := protosFor(r.Proto)
		for _, p := range protos {
			iptablesEnsure([]string{
				"-t", "nat", "-A", "PREROUTING",
				"-p", p, "--dport", fmt.Sprint(r.ListenPort),
				"-j", "DNAT", "--to-destination", target,
			})
			// also forward on OUTPUT so locally-originated traffic works
			iptablesEnsure([]string{
				"-t", "nat", "-A", "OUTPUT",
				"-p", p, "--dport", fmt.Sprint(r.ListenPort),
				"-j", "DNAT", "--to-destination", target,
			})
		}
		logInfo(fmt.Sprintf("  :%d → %s  (%s)", r.ListenPort, target, r.Proto))
	}

	// MASQUERADE so return traffic is properly rewritten
	iptablesEnsure([]string{"-t", "nat", "-A", "POSTROUTING",
		"-d", peerIP, "-j", "MASQUERADE"})
	logInfo("forward rules applied")
}

// RemoveForward removes all DNAT rules that were added by ApplyForward.
func RemoveForward(peerIP string, rules []ForwardRule) {
	for _, r := range rules {
		target := fmt.Sprintf("%s:%d", peerIP, r.TargetPort)
		for _, p := range protosFor(r.Proto) {
			try("iptables", "-t", "nat", "-D", "PREROUTING",
				"-p", p, "--dport", fmt.Sprint(r.ListenPort),
				"-j", "DNAT", "--to-destination", target)
			try("iptables", "-t", "nat", "-D", "OUTPUT",
				"-p", p, "--dport", fmt.Sprint(r.ListenPort),
				"-j", "DNAT", "--to-destination", target)
		}
	}
	try("iptables", "-t", "nat", "-D", "POSTROUTING",
		"-d", peerIP, "-j", "MASQUERADE")
}

func protosFor(p string) []string {
	if p == "tcp" {
		return []string{"tcp"}
	}
	if p == "udp" {
		return []string{"udp"}
	}
	return []string{"tcp", "udp"} // "both"
}
