package vault

import (
	"testing"
	"time"
)

func TestNewSecretStoreAlerter_NotNil(t *testing.T) {
	scanner := NewSecretStoreScanner(&Client{}, "secret")
	a := NewSecretStoreAlerter(scanner, DefaultSecretStoreThresholds())
	if a == nil {
		t.Fatal("expected non-nil alerter")
	}
}

func TestNewSecretStoreAlerter_NilScanner(t *testing.T) {
	a := NewSecretStoreAlerter(nil, DefaultSecretStoreThresholds())
	if a != nil {
		t.Fatal("expected nil alerter for nil scanner")
	}
}

func TestDefaultSecretStoreThresholds_NotEmpty(t *testing.T) {
	th := DefaultSecretStoreThresholds()
	if th.Warning == 0 || th.Critical == 0 {
		t.Fatal("expected non-zero thresholds")
	}
}

func TestSecretStoreAlerter_Evaluate_NoAlert(t *testing.T) {
	scanner := NewSecretStoreScanner(&Client{}, "secret")
	a := NewSecretStoreAlerter(scanner, DefaultSecretStoreThresholds())
	entries := []*SecretStoreEntry{
		{Path: "apps/token", ExpiresAt: time.Now().Add(7 * 24 * time.Hour)},
	}
	alerts := a.Evaluate(entries)
	if len(alerts) != 0 {
		t.Fatalf("expected 0 alerts, got %d", len(alerts))
	}
}

func TestSecretStoreAlerter_Evaluate_WarningAlert(t *testing.T) {
	scanner := NewSecretStoreScanner(&Client{}, "secret")
	a := NewSecretStoreAlerter(scanner, DefaultSecretStoreThresholds())
	entries := []*SecretStoreEntry{
		{Path: "apps/token", ExpiresAt: time.Now().Add(48 * time.Hour)},
	}
	alerts := a.Evaluate(entries)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Severity != SeverityWarning {
		t.Fatalf("expected warning severity, got %s", alerts[0].Severity)
	}
}

func TestSecretStoreAlerter_Evaluate_CriticalAlert(t *testing.T) {
	scanner := NewSecretStoreScanner(&Client{}, "secret")
	a := NewSecretStoreAlerter(scanner, DefaultSecretStoreThresholds())
	entries := []*SecretStoreEntry{
		{Path: "apps/db", ExpiresAt: time.Now().Add(10 * time.Hour)},
	}
	alerts := a.Evaluate(entries)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Severity != SeverityCritical {
		t.Fatalf("expected critical severity, got %s", alerts[0].Severity)
	}
}

func TestSecretStoreAlerter_Evaluate_NilEntry(t *testing.T) {
	scanner := NewSecretStoreScanner(&Client{}, "secret")
	a := NewSecretStoreAlerter(scanner, DefaultSecretStoreThresholds())
	alerts := a.Evaluate([]*SecretStoreEntry{nil})
	if len(alerts) != 0 {
		t.Fatalf("expected 0 alerts for nil entry, got %d", len(alerts))
	}
}
