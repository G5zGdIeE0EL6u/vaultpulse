package vault

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newMaintenanceAlertServer(enabled bool) *httptest.Server {
	return newMaintenanceTestServer(enabled, http.StatusOK)
}

func TestNewMaintenanceAlerter_NotNil(t *testing.T) {
	c := &Client{}
	mc, _ := NewMaintenanceChecker(c)
	ma, err := NewMaintenanceAlerter(mc, "https://vault.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ma == nil {
		t.Fatal("expected non-nil MaintenanceAlerter")
	}
}

func TestNewMaintenanceAlerter_NilChecker(t *testing.T) {
	_, err := NewMaintenanceAlerter(nil, "https://vault.example.com")
	if err == nil {
		t.Fatal("expected error for nil checker")
	}
}

func TestMaintenanceAlerter_Evaluate_NoAlert(t *testing.T) {
	srv := newMaintenanceAlertServer(false)
	defer srv.Close()

	c, _ := NewClient(srv.URL, "test-token")
	mc, _ := NewMaintenanceChecker(c)
	ma, _ := NewMaintenanceAlerter(mc, srv.URL)

	alert, err := ma.Evaluate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alert != nil {
		t.Errorf("expected no alert, got: %v", alert)
	}
}

func TestMaintenanceAlerter_Evaluate_CriticalAlert(t *testing.T) {
	srv := newMaintenanceAlertServer(true)
	defer srv.Close()

	c, _ := NewClient(srv.URL, "test-token")
	mc, _ := NewMaintenanceChecker(c)
	ma, _ := NewMaintenanceAlerter(mc, srv.URL)

	alert, err := ma.Evaluate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alert == nil {
		t.Fatal("expected a critical alert")
	}
	if alert.Severity != SeverityCritical {
		t.Errorf("expected severity %q, got %q", SeverityCritical, alert.Severity)
	}
	if !strings.Contains(alert.String(), "maintenance mode") {
		t.Errorf("alert string missing 'maintenance mode': %s", alert.String())
	}
}

func TestMaintenanceAlert_String_ContainsNodeAddress(t *testing.T) {
	srv := newMaintenanceAlertServer(true)
	defer srv.Close()

	c, _ := NewClient(srv.URL, "test-token")
	mc, _ := NewMaintenanceChecker(c)
	ma, _ := NewMaintenanceAlerter(mc, "vault-node-1")

	alert, _ := ma.Evaluate()
	if alert == nil {
		t.Fatal("expected alert")
	}
	if !strings.Contains(alert.String(), "vault-node-1") {
		t.Errorf("expected node address in alert string: %s", alert.String())
	}
}
