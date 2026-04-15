package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the top-level vaultpulse configuration.
type Config struct {
	Vault   VaultConfig   `yaml:"vault"`
	Alerting AlertingConfig `yaml:"alerting"`
	PollInterval time.Duration `yaml:"poll_interval"`
}

// VaultConfig holds Vault connection settings.
type VaultConfig struct {
	Address   string `yaml:"address"`
	Token     string `yaml:"token"`
	Namespace string `yaml:"namespace"`
	TLSSkipVerify bool `yaml:"tls_skip_verify"`
}

// AlertingConfig holds alerting hook configuration.
type AlertingConfig struct {
	WebhookURL      string        `yaml:"webhook_url"`
	ExpiryThreshold time.Duration `yaml:"expiry_threshold"`
	SlackChannel    string        `yaml:"slack_channel"`
}

// Load reads and parses a YAML config file from the given path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %q: %w", path, err)
	}

	cfg := &Config{
		PollInterval: 60 * time.Second,
		Alerting: AlertingConfig{
			ExpiryThreshold: 24 * time.Hour,
		},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %q: %w", path, err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

// validate checks that required fields are present.
func (c *Config) validate() error {
	if c.Vault.Address == "" {
		return fmt.Errorf("vault.address is required")
	}
	if c.Vault.Token == "" {
		// Fall back to VAULT_TOKEN env var
		c.Vault.Token = os.Getenv("VAULT_TOKEN")
	}
	if c.Vault.Token == "" {
		return fmt.Errorf("vault.token or VAULT_TOKEN env var is required")
	}
	if c.PollInterval < 5*time.Second {
		return fmt.Errorf("poll_interval must be at least 5s")
	}
	return nil
}
