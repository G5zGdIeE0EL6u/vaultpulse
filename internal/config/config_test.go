package config

import (
	"os"
	"testing"
	"time"
)

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "vaultpulse-*.yaml")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	f.Close()
	return f.Name()
}

func TestLoad_ValidConfig(t *testing.T) {
	path := writeTempConfig(t, `
vault:
  address: "https://vault.example.com"
  token: "s.testtoken"
poll_interval: 30s
alerting:
  webhook_url: "https://hooks.example.com/alert"
  expiry_threshold: 48h
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Vault.Address != "https://vault.example.com" {
		t.Errorf("expected vault address, got %q", cfg.Vault.Address)
	}
	if cfg.PollInterval != 30*time.Second {
		t.Errorf("expected 30s poll interval, got %v", cfg.PollInterval)
	}
	if cfg.Alerting.ExpiryThreshold != 48*time.Hour {
		t.Errorf("expected 48h expiry threshold, got %v", cfg.Alerting.ExpiryThreshold)
	}
}

func TestLoad_DefaultsApplied(t *testing.T) {
	path := writeTempConfig(t, `
vault:
  address: "https://vault.example.com"
  token: "s.testtoken"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PollInterval != 60*time.Second {
		t.Errorf("expected default 60s poll interval, got %v", cfg.PollInterval)
	}
	if cfg.Alerting.ExpiryThreshold != 24*time.Hour {
		t.Errorf("expected default 24h expiry threshold, got %v", cfg.Alerting.ExpiryThreshold)
	}
}

func TestLoad_MissingAddress(t *testing.T) {
	path := writeTempConfig(t, `
vault:
  token: "s.testtoken"
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for missing vault address")
	}
}

func TestLoad_TokenFromEnv(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "s.envtoken")
	path := writeTempConfig(t, `
vault:
  address: "https://vault.example.com"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Vault.Token != "s.envtoken" {
		t.Errorf("expected token from env, got %q", cfg.Vault.Token)
	}
}
