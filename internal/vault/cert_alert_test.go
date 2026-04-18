package vault

import (
	"testing"
	"time"
)

func TestNewCertAlerter_NotNil(t *testing.T) {
	scanner := &CertScanner{mount: "pki"}
	a, err := NewCertAlerter(scanner, DefaultCertAlertThresholds())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a == nil {
		t.Fatal("expected non-nil alerter")
	}
}

func TestNewCertAlerter_NilScanner(t *testing.T) {
	_, err := NewCertAlerter(nil, DefaultCertAlertThresholds())
	if err == nil {
		t.Fatal("expected error for nil scanner")
	}
}

func TestDefaultCertAlertThresholds_NotEmpty(t *testing.T) {
	th := DefaultCertAlertThresholds()
	if th.Critical == 0 || th.Warning == 0 {
		t.Error("expected non-zero thresholds")
	}
}

func TestCertAlerter_Evaluate_NoAlert(t *testing.T) {
	scanner := &CertScanner{mount: "pki"}
	a, _ := NewCertAlerter(scanner, DefaultCertAlertThresholds())
	cert := &CertInfo{Serial: "aa", Expiry: time.Now().Add(60 * 24 * time.Hour)}
	if a.Evaluate(cert) != nil {
		t.Error("expected no alert")
	}
}

func TestCertAlerter_Evaluate_WarningAlert(t *testing.T) {
	scanner := &CertScanner{mount: "pki"}
	a, _ := NewCertAlerter(scanner, DefaultCertAlertThresholds())
	cert := &CertInfo{Serial: "bb", Expiry: time.Now().Add(10 * 24 * time.Hour)}
	alert := a.Evaluate(cert)
	if alert == nil {
		t.Fatal("expected warning alert")
	}
	if alert.Severity != SeverityWarning {
		t.Errorf("expected warning, got %v", alert.Severity)
	}
}

func TestCertAlerter_Evaluate_CriticalAlert(t *testing.T) {
	scanner := &CertScanner{mount: "pki"}
	a, _ := NewCertAlerter(scanner, DefaultCertAlertThresholds())
	cert := &CertInfo{Serial: "cc", Expiry: time.Now().Add(2 * 24 * time.Hour)}
	alert := a.Evaluate(cert)
	if alert == nil {
		t.Fatal("expected critical alert")
	}
	if alert.Severity != SeverityCritical {
		t.Errorf("expected critical, got %v", alert.Severity)
	}
}

func TestCertAlerter_Evaluate_RevokedSkipped(t *testing.T) {
	scanner := &CertScanner{mount: "pki"}
	a, _ := NewCertAlerter(scanner, DefaultCertAlertThresholds())
	cert := &CertInfo{Serial: "dd", Expiry: time.Now().Add(time.Hour), Revoked: true}
	if a.Evaluate(cert) != nil {
		t.Error("expected no alert for revoked cert")
	}
}
