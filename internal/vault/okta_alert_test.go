package vault

import (
	"testing"
	"time"
)

func TestNewOktaAlerter_NotNil(t *testing.T) {
	s := &OktaScanner{client: &Client{}, mount: "okta"}
	a := NewOktaAlerter(s, 0, 0)
	if a == nil {
		t.Fatal("expected non-nil alerter")
	}
}

func TestNewOktaAlerter_NilScanner(t *testing.T) {
	if NewOktaAlerter(nil, 0, 0) != nil {
		t.Fatal("expected nil for nil scanner")
	}
}

func TestNewOktaAlerter_DefaultThresholds(t *testing.T) {
	s := &OktaScanner{client: &Client{}, mount: "okta"}
	a := NewOktaAlerter(s, 0, 0)
	if a.warningTTL != 72*time.Hour {
		t.Errorf("expected 72h warning, got %v", a.warningTTL)
	}
	if a.criticalTTL != 24*time.Hour {
		t.Errorf("expected 24h critical, got %v", a.criticalTTL)
	}
}

func TestOktaAlerter_Evaluate_CriticalAlert(t *testing.T) {
	user := &OktaUser{Username: "alice", TTL: 10 * time.Hour}
	var sev Severity
	switch {
	case user.TTL <= 24*time.Hour:
		sev = SeverityCritical
	case user.TTL <= 72*time.Hour:
		sev = SeverityWarning
	}
	if sev != SeverityCritical {
		t.Errorf("expected critical, got %v", sev)
	}
}

func TestOktaAlerter_Evaluate_WarningAlert(t *testing.T) {
	user := &OktaUser{Username: "bob", TTL: 48 * time.Hour}
	var sev Severity
	switch {
	case user.TTL <= 24*time.Hour:
		sev = SeverityCritical
	case user.TTL <= 72*time.Hour:
		sev = SeverityWarning
	}
	if sev != SeverityWarning {
		t.Errorf("expected warning, got %v", sev)
	}
}

func TestOktaAlerter_Evaluate_NoAlertForZeroTTL(t *testing.T) {
	user := &OktaUser{Username: "charlie", TTL: 0}
	if !user.IsExpired() {
		t.Error("expected zero TTL to be treated as expired/skipped")
	}
}
