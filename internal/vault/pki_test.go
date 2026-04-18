package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newPKITestServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/pki/roles":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"keys": []string{"web", "internal"}},
			})
		case "/v1/pki/roles/web":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"max_ttl":         "48h",
					"ttl":             "24h",
					"allowed_domains": []string{"example.com"},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestNewPKIScanner_NotNil(t *testing.T) {
	s := newPKITestServer()
	defer s.Close()
	client, _ := NewClient(s.URL, "token")
	scanner := NewPKIScanner(client, "")
	if scanner == nil {
		t.Fatal("expected non-nil scanner")
	}
}

func TestNewPKIScanner_NilClient(t *testing.T) {
	if NewPKIScanner(nil, "pki") != nil {
		t.Fatal("expected nil for nil client")
	}
}

func TestPKIListRoles_Success(t *testing.T) {
	s := newPKITestServer()
	defer s.Close()
	client, _ := NewClient(s.URL, "token")
	scanner := NewPKIScanner(client, "pki")
	roles, err := scanner.ListRoles()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roles) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(roles))
	}
}

func TestPKIGetRole_Success(t *testing.T) {
	s := newPKITestServer()
	defer s.Close()
	client, _ := NewClient(s.URL, "token")
	scanner := NewPKIScanner(client, "pki")
	role, err := scanner.GetRole("web")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if role.MaxTTL != 48*time.Hour {
		t.Errorf("expected 48h max_ttl, got %s", role.MaxTTL)
	}
}

func TestNewPKIAlerter_NotNil(t *testing.T) {
	s := newPKITestServer()
	defer s.Close()
	client, _ := NewClient(s.URL, "token")
	scanner := NewPKIScanner(client, "pki")
	alerter := NewPKIAlerter(scanner, 0, 0)
	if alerter == nil {
		t.Fatal("expected non-nil alerter")
	}
}

func TestPKIAlerter_Evaluate_WarningAlert(t *testing.T) {
	s := newPKITestServer()
	defer s.Close()
	client, _ := NewClient(s.URL, "token")
	scanner := NewPKIScanner(client, "pki")
	// 48h role MaxTTL, warning threshold 72h → should warn
	alerter := NewPKIAlerter(scanner, 24*time.Hour, 72*time.Hour)
	alerts, err := alerter.Evaluate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) == 0 {
		t.Fatal("expected at least one alert")
	}
	if alerts[0].Severity != SeverityWarning {
		t.Errorf("expected warning severity, got %s", alerts[0].Severity)
	}
}
