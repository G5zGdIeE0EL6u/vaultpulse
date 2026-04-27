package vault

import (
	"testing"
	"time"
)

func TestNewTokenTTLAlerter_NotNil(t *testing.T) {
	c, _ := NewClient("http://localhost", "token")
	s := NewTokenTTLScanner(c, "")
	a := NewTokenTTLAlerter(s, nil)
	if a == nil {
		t.Fatal("expected non-nil alerter")
	}
}

func TestNewTokenTTLAlerter_NilScanner(t *testing.T) {
	if NewTokenTTLAlerter(nil, nil) != nil {
		t.Fatal("expected nil for nil scanner")
	}
}

func TestDefaultTokenTTLThresholds_NotEmpty(t *testing.T) {
	th := DefaultTokenTTLThresholds()
	if len(th) == 0 {
		t.Fatal("expected non-empty thresholds")
	}
	if _, ok := th["warning"]; !ok {
		t.Error("missing warning threshold")
	}
	if _, ok := th["critical"]; !ok {
		t.Error("missing critical threshold")
	}
}

func TestTokenTTLAlerter_Evaluate_NoAlert(t *testing.T) {
	c, _ := NewClient("http://localhost", "token")
	s := NewTokenTTLScanner(c, "")
	a := NewTokenTTLAlerter(s, nil)
	entry := &TokenTTLEntry{
		Accessor:    "acc-1",
		DisplayName: "healthy-token",
		TTL:         48 * time.Hour,
	}
	if alert := a.Evaluate(entry); alert != nil {
		t.Errorf("expected no alert, got %+v", alert)
	}
}

func TestTokenTTLAlerter_Evaluate_WarningAlert(t *testing.T) {
	c, _ := NewClient("http://localhost", "token")
	s := NewTokenTTLScanner(c, "")
	a := NewTokenTTLAlerter(s, nil)
	entry := &TokenTTLEntry{
		Accessor:    "acc-2",
		DisplayName: "warn-token",
		TTL:         12 * time.Hour,
	}
	alert := a.Evaluate(entry)
	if alert == nil {
		t.Fatal("expected warning alert")
	}
	if alert.Severity != SeverityWarning {
		t.Errorf("expected warning, got %v", alert.Severity)
	}
}

func TestTokenTTLAlerter_Evaluate_CriticalAlert(t *testing.T) {
	c, _ := NewClient("http://localhost", "token")
	s := NewTokenTTLScanner(c, "")
	a := NewTokenTTLAlerter(s, nil)
	entry := &TokenTTLEntry{
		Accessor:    "acc-3",
		DisplayName: "crit-token",
		TTL:         1 * time.Hour,
	}
	alert := a.Evaluate(entry)
	if alert == nil {
		t.Fatal("expected critical alert")
	}
	if alert.Severity != SeverityCritical {
		t.Errorf("expected critical, got %v", alert.Severity)
	}
}

func TestTokenTTLAlerter_Evaluate_NilEntry(t *testing.T) {
	c, _ := NewClient("http://localhost", "token")
	s := NewTokenTTLScanner(c, "")
	a := NewTokenTTLAlerter(s, nil)
	if alert := a.Evaluate(nil); alert != nil {
		t.Errorf("expected nil alert for nil entry, got %+v", alert)
	}
}
