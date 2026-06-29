package webpanel

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

const DefaultConfigsDir = "/opt/virlink/configs"

// Config is read from webpanel.toml (central dashboard service).
type Config struct {
	Listen       string `toml:"listen"`
	Username     string `toml:"username"`
	PasswordHash string `toml:"password_hash"`
	ConfigsDir   string `toml:"configs_dir"`
}

func LoadConfig(path string) (*Config, error) {
	var wrapper struct {
		Webpanel Config `toml:"webpanel"`
	}
	if _, err := toml.DecodeFile(path, &wrapper); err != nil {
		return nil, fmt.Errorf("webpanel config: %w", err)
	}
	c := wrapper.Webpanel
	if c.Listen == "" {
		c.Listen = "0.0.0.0:8787"
	}
	if c.ConfigsDir == "" {
		c.ConfigsDir = DefaultConfigsDir
	}
	if c.Username == "" {
		return nil, fmt.Errorf("webpanel: username is required")
	}
	if c.PasswordHash == "" {
		return nil, fmt.Errorf("webpanel: password_hash is required")
	}
	if _, err := os.Stat(c.ConfigsDir); err != nil {
		return nil, fmt.Errorf("webpanel: configs_dir %q: %w", c.ConfigsDir, err)
	}
	return &c, nil
}
