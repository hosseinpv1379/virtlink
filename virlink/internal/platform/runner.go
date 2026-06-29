// runner.go — subprocess helpers (modprobe, ip fou, ip l2tp, wg, iptables).
// Network objects (links, addresses, routes) are created natively via netlink
// in netops.go. This file only wraps external commands that have no kernel API.
package platform

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// run executes a command; returns a descriptive error on failure.
func Run(name string, args ...string) error {
	logDebug("exec: " + name + " " + strings.Join(args, " "))
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("%s", msg)
		}
		return fmt.Errorf("%s %s: %v", name, strings.Join(args, " "), err)
	}
	return nil
}

// runOut runs a command and returns its combined output.
func RunOut(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// try runs a command, silently ignoring errors (best-effort cleanup).
func Try(name string, args ...string) {
	_ = run(name, args...)
}
