package vault

import (
	"testing"
	"time"
)

func TestNewAWSAlerter_NotNil(t *testing.T) {
	s := &AWSScanner{}
	a := NewAWSAlerter(s)
	if a == nil {
		t.Fatal("expected non-nil alerter")
	}
}

func TestNewAWSAlerter_NilScanner(t *testing.T) {
	if NewAWSAlerter(nil) != nil {
		t.Fatal("expected nil for nil scanner")
	}
}

func TestAWSAlerter_Evaluate_NoAlert(t *testing.T) {
	a := NewAWSAlerter(&AWSScanner{})
	cred := &AWSCredential{LeaseExpiry: time.Now().Add(168 * time.Hour)}
	if a.Evaluate(cred, "my-role") != nil {
		t.Fatal("expected no alert for healthy credential")
	}
}

func TestAWSAlerter_Evaluate_WarningAlert(t *testing.T) {
	a := NewAWSAlerter(&AWSScanner{})
	cred := &AWSCredential{LeaseExpiry: time.Now().Add(48 * time.Hour)}
	alert := a.Evaluate(cred, "dev-role")
	if alert == nil {
		t.Fatal("expected warning alert")
	}
	if alert.Severity != SeverityWarning {
		t.Fatalf("expected warning severity, got %s", alert.Severity)
	}
}

func TestAWSAlerter_Evaluate_CriticalAlert(t *testing.T) {
	a := NewAWSAlerter(&AWSScanner{})
	cred := &AWSCredential{LeaseExpiry: time.Now().Add(12 * time.Hour)}
	alert := a.Evaluate(cred, "prod-role")
	if alert == nil {
		t.Fatal("expected critical alert")
	}
	if alert.Severity != SeverityCritical {
		t.Fatalf("expected critical severity, got %s", alert.Severity)
	}
}

func TestAWSAlerter_Evaluate_Expired(t *testing.T) {
	a := NewAWSAlerter(&AWSScanner{})
	cred := &AWSCredential{LeaseExpiry: time.Now().Add(-time.Minute)}
	alert := a.Evaluate(cred, "old-role")
	if alert == nil {
		t.Fatal("expected alert for expired credential")
	}
	if alert.Severity != SeverityCritical {
		t.Fatalf("expected critical severity, got %s", alert.Severity)
	}
}

func TestAWSAlerter_Evaluate_NilCred(t *testing.T) {
	a := NewAWSAlerter(&AWSScanner{})
	if a.Evaluate(nil, "role") != nil {
		t.Fatal("expected nil alert for nil credential")
	}
}
