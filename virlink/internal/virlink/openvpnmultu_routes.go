// openvpnmultu_routes.go — overlay /32 routes with correct src (lo), ECMP across workers.
package virlink

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func openvpnMultuWriteRouteScripts(runtimeDir string, c *Config, localPlain, peer string) error {
	n := c.OpenVPNMultu.Workers
	var workers []string
	for i := 0; i < n; i++ {
		workers = append(workers, openvpnMultuWorkerDev(c, i))
	}
	workersLine := strings.Join(workers, " ")

	syncSh := fmt.Sprintf(`#!/bin/bash
# virlink openvpnmultu — rebuild peer overlay route(s) with src=%s
set -euo pipefail
PEER=%q
LOCAL=%q
WORKERS=(%s)

active=()
for d in "${WORKERS[@]}"; do
  ip link show "$d" 2>/dev/null | grep -q ' state UP' && active+=("$d")
done

ip route del "${PEER}/32" 2>/dev/null || true
(( ${#active[@]} == 0 )) && exit 0

if (( ${#active[@]} == 1 )); then
  ip route add "${PEER}/32" dev "${active[0]}" src "${LOCAL}"
else
  args=(route add "${PEER}/32" src "${LOCAL}")
  for d in "${active[@]}"; do
    args+=(nexthop dev "$d" weight 1)
  done
  ip "${args[@]}"
fi
`, localPlain, peer, localPlain, workersLine)

	upSh := fmt.Sprintf(`#!/bin/bash
# virlink openvpnmultu — worker session up (%s → %s)
set -euo pipefail
exec %q/overlay-sync.sh
`, localPlain, peer, runtimeDir)

	downSh := fmt.Sprintf(`#!/bin/bash
set -euo pipefail
exec %q/overlay-sync.sh
`, runtimeDir)

	for name, body := range map[string]string{
		"overlay-sync.sh": syncSh,
		"overlay-up.sh":   upSh,
		"overlay-down.sh": downSh,
	} {
		p := filepath.Join(runtimeDir, name)
		if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
			return fmt.Errorf("write %s: %w", p, err)
		}
	}
	return nil
}

func openvpnMultuOverlayRouteBlock(runtimeDir string) string {
	up := filepath.Join(runtimeDir, "overlay-up.sh")
	down := filepath.Join(runtimeDir, "overlay-down.sh")
	return fmt.Sprintf(`
# virlink openvpnmultu — overlay peer route with src on lo (ECMP when all workers up)
script-security 2
up %s
down %s
`, up, down)
}
