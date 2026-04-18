package vault

import (
	"testing"
	"time"
)

func TestNewLDAPAlerter_NotNil(t *testing.T) {
	s, _ := NewLDAPScanner(&Client{}, "ldap")
	a, err := NewLDAPAlerter(s, 0, 0)
	if err != nil || a == nil {
		t.Fatal("expected non-nil alerter")
	}
}

func TestNewLDAPAlerter_NilScanner(t *testing.T) {
	_, err := NewLDAPAlerter(nil, 0, 0)
	if err == nil {
		t.Fatal("expected error for nil scanner")
	}
}

func TestNewLDAPAlerter_DefaultThresholds(t *testing.T) {
	s, _ := NewLDAPScanner(&Client{}, "ldap")
	a, _ := NewLDAPAlerter(s, 0, 0)
	if a.warningTTL != 72*time.Hour {
		t.Errorf("expected 72h warning, got %v", a.warningTTL)
	}
	if a.criticalTTL != 24*time.Hour {
		t.Errorf("expected 24h critical, got %v", a.criticalTTL)
	}
}

func TestLDAPAlerter_Evaluate_CriticalAlert(t *testing.T) {
	srv := newLDAPTestServer()
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	s, _ := NewLDAPScanner(c, "ldap")
	// Use very large thresholds so any TTL triggers critical
	a, _ := NewLDAPAlerter(s, 999*time.Hour, 999*time.Hour)
	alerts, err := a.Evaluate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, al := range alerts {
		if al.Severity != SeverityCritical {
			t.Errorf("expected critical, got %v", al.Severity)
		}
	}
}

func TestLDAPAlerter_Evaluate_NoAlertForZeroTTL(t *testing.T) {
	srv := newLDAPTestServer()
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	s, _ := NewLDAPScanner(c, "ldap")
	a, _ := NewLDAPAlerter(s, time.Minute, time.Second)
	alerts, err := a.Evaluate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, al := range alerts {
		if al.Path == "auth/ldap/groups/devs" {
			t.Error("expected no alert for zero-TTL role")
		}
	}
}
