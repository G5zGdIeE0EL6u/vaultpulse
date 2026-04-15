package vault_test

import (
	"testing"
	"time"

	"github.com/vaultpulse/vaultpulse/internal/vault"
)

func TestAlert_String(t *testing.T) {
	expiry := time.Now().Add(10 * time.Minute)
	a := vault.Alert{
		Path:      "secret/data/myapp",
		ExpiresAt: expiry,
		TTL:       10 * time.Minute,
		LeaseID:   "lease-abc-123",
		Severity:  vault.SeverityWarning,
	}

	s := a.String()
	if s == "" {
		t.Error("expected non-empty alert string")
	}
}

func TestAlert_IsExpired_False(t *testing.T) {
	a := vault.Alert{ExpiresAt: time.Now().Add(1 * time.Hour)}
	if a.IsExpired() {
		t.Error("expected alert to not be expired")
	}
}

func TestAlert_IsExpired_True(t *testing.T) {
	a := vault.Alert{ExpiresAt: time.Now().Add(-1 * time.Second)}
	if !a.IsExpired() {
		t.Error("expected alert to be expired")
	}
}

func TestAlert_TimeUntilExpiry(t *testing.T) {
	expected := 30 * time.Minute
	a := vault.Alert{ExpiresAt: time.Now().Add(expected)}
	remaining := a.TimeUntilExpiry()
	if remaining <= 0 {
		t.Errorf("expected positive remaining time, got %s", remaining)
	}
}

func TestNewMonitor_NotNil(t *testing.T) {
	srv := newMockVaultServer(t, nil)
	client, err := vault.NewClient(srv.URL, "token")
	if err != nil {
		t.Fatalf("client setup: %v", err)
	}

	mon := vault.NewMonitor(client, vault.MonitorConfig{
		Paths:            []string{"secret/data/test"},
		PollInterval:     5 * time.Second,
		WarningThreshold: 15 * time.Minute,
	})

	if mon == nil {
		t.Fatal("expected non-nil monitor")
	}
	if mon.Alerts() == nil {
		t.Fatal("expected non-nil alerts channel")
	}
}
