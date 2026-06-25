// keygen.go — WireGuard keypair helper (`virlink keygen`).
package virlink

import (
	"fmt"
	"os"
	"strings"
)

// keygen generates a WireGuard keypair using `wg genkey` / `wg pubkey`.
// Usage: ./virlink keygen
func keygen() {
	if _, err := runOut("which", "wg"); err != nil {
		fmt.Fprintln(os.Stderr, "❌  wg not found — install: apt install wireguard-tools")
		os.Exit(1)
	}

	privRaw, err := runOut("wg", "genkey")
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌  wg genkey: %v\n", err)
		os.Exit(1)
	}
	privKey := strings.TrimSpace(privRaw)

	// pipe privkey into wg pubkey via shell
	f, err := os.CreateTemp("", "wg-key-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer os.Remove(f.Name())
	_ = os.Chmod(f.Name(), 0600)
	fmt.Fprintln(f, privKey)
	f.Close()

	pubRaw, err := runOut("sh", "-c", "wg pubkey < "+f.Name())
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌  wg pubkey: %v\n", err)
		os.Exit(1)
	}
	pubKey := strings.TrimSpace(pubRaw)

	fmt.Printf(`
  ✅  WireGuard keypair
  ─────────────────────────────────────────────
  private_key = %q
  public_key  = %q
  ─────────────────────────────────────────────

  Run on both servers, then add to config.toml:

  [gre_wg]
  client_private_key = "<client privkey>"
  client_public_key  = "<client pubkey>"
  server_private_key = "<server privkey>"
  server_public_key  = "<server pubkey>"

`, privKey, pubKey)
}
