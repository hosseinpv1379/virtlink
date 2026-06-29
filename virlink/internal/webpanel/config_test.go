package webpanel

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigWebpanelSection(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "webpanel.toml")
	if err := os.WriteFile(cfgPath, []byte(`
[webpanel]
listen = "127.0.0.1:8787"
username = "admin"
password_hash = "sha256:abc"
configs_dir = "`+dir+`"
`), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if c.Username != "admin" || c.Listen != "127.0.0.1:8787" {
		t.Fatalf("unexpected config: %+v", c)
	}
}
