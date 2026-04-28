package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newControlGroupTestServer(t *testing.T, accessor string, expiresIn time.Duration, approved bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		payload := map[string]interface{}{
			"data": map[string]interface{}{
				"accessor":        accessor,
				"creation_path":   "secret/data/myapp",
				"creation_time":   now.Format(time.RFC3339),
				"expiration_time": now.Add(expiresIn).Format(time.RFC3339),
				"approved":        approved,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(payload)
	}))
}

func TestNewControlGroupScanner_NotNil(t *testing.T) {
	client, _ := NewClient("http://127.0.0.1:8200", "test-token")
	s := NewControlGroupScanner(client)
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
}

func TestNewControlGroupScanner_NilClient(t *testing.T) {
	s := NewControlGroupScanner(nil)
	if s != nil {
		t.Fatal("expected nil scanner for nil client")
	}
}

func TestControlGroupGetRequest_EmptyAccessor(t *testing.T) {
	client, _ := NewClient("http://127.0.0.1:8200", "test-token")
	s := NewControlGroupScanner(client)
	_, err := s.GetRequest("")
	if err == nil {
		t.Fatal("expected error for empty accessor")
	}
}

func TestControlGroupGetRequest_Success(t *testing.T) {
	const accessor = "abc-123"
	srv := newControlGroupTestServer(t, accessor, 90*time.Minute, false)
	defer srv.Close()

	client, _ := NewClient(srv.URL, "test-token")
	s := NewControlGroupScanner(client)

	req, err := s.GetRequest(accessor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Accessor != accessor {
		t.Errorf("expected accessor %q, got %q", accessor, req.Accessor)
	}
	if req.IsExpired() {
		t.Error("expected request to not be expired")
	}
}

func TestNewControlGroupAlerter_NotNil(t *testing.T) {
	client, _ := NewClient("http://127.0.0.1:8200", "test-token")
	s := NewControlGroupScanner(client)
	a := NewControlGroupAlerter(s, 0, 0)
	if a == nil {
		t.Fatal("expected non-nil alerter")
	}
}

func TestNewControlGroupAlerter_NilScanner(t *testing.T) {
	a := NewControlGroupAlerter(nil, 0, 0)
	if a != nil {
		t.Fatal("expected nil alerter for nil scanner")
	}
}

func TestControlGroupAlerter_Evaluate_WarningAlert(t *testing.T) {
	srv := newControlGroupTestServer(t, "warn-accessor", 90*time.Minute, false)
	defer srv.Close()

	client, _ := NewClient(srv.URL, "test-token")
	s := NewControlGroupScanner(client)
	a := NewControlGroupAlerter(s, 2*time.Hour, 30*time.Minute)

	alert, err := a.Evaluate("warn-accessor")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alert == nil {
		t.Fatal("expected a warning alert")
	}
	if alert.Severity != SeverityWarning {
		t.Errorf("expected warning severity, got %s", alert.Severity)
	}
}

func TestControlGroupAlerter_Evaluate_NoAlert(t *testing.T) {
	srv := newControlGroupTestServer(t, "ok-accessor", 5*time.Hour, false)
	defer srv.Close()

	client, _ := NewClient(srv.URL, "test-token")
	s := NewControlGroupScanner(client)
	a := NewControlGroupAlerter(s, 2*time.Hour, 30*time.Minute)

	alert, err := a.Evaluate("ok-accessor")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alert != nil {
		t.Errorf("expected no alert, got %+v", alert)
	}
}
