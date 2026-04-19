package vault

import (
	"testing"
	"time"
)

func TestNewAzureAlerter_NotNil(t *testing.T) {
	srv := newAzureTestServer()
	defer srv.Close()
	client, _ := NewClient(srv.URL, "test-token")
	scanner := NewAzureScanner(client, "azure")
	alerter, err := NewAzureAlerter(scanner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alerter == nil {
		t.Fatal("expected non-nil alerter")
	}
}

func TestNewAzureAlerter_NilScanner(t *testing.T) {
	_, err := NewAzureAlerter(nil)
	if err == nil {
		t.Fatal("expected error for nil scanner")
	}
}

func TestAzureAlerter_Evaluate_WarningAlert(t *testing.T) {
	srv := newAzureTestServer()
	defer srv.Close()
	client, _ := NewClient(srv.URL, "test-token")
	scanner := NewAzureScanner(client, "azure")
	alerter, _ := NewAzureAlerter(scanner)
	// 48h TTL falls within warning threshold (72h)
	alerter.warningTTL = 72 * time.Hour
	alerter.criticalTTL = 24 * time.Hour
	alerts, err := alerter.Evaluate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Severity != SeverityWarning {
		t.Errorf("expected warning severity, got %v", alerts[0].Severity)
	}
}

func TestAzureAlerter_Evaluate_CriticalAlert(t *testing.T) {
	srv := newAzureTestServer()
	defer srv.Close()
	client, _ := NewClient(srv.URL, "test-token")
	scanner := NewAzureScanner(client, "azure")
	alerter, _ := NewAzureAlerter(scanner)
	// lower thresholds so 48h TTL is critical
	alerter.warningTTL = 96 * time.Hour
	alerter.criticalTTL = 72 * time.Hour
	alerts, err := alerter.Evaluate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Severity != SeverityCritical {
		t.Errorf("expected critical severity, got %v", alerts[0].Severity)
	}
}

func TestAzureAlerter_Evaluate_NoAlert(t *testing.T) {
	srv := newAzureTestServer()
	defer srv.Close()
	client, _ := NewClient(srv.URL, "test-token")
	scanner := NewAzureScanner(client, "azure")
	alerter, _ := NewAzureAlerter(scanner)
	// very low thresholds so 48h TTL doesn't trigger
	alerter.warningTTL = 12 * time.Hour
	alerter.criticalTTL = 6 * time.Hour
	alerts, err := alerter.Evaluate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(alerts))
	}
}
