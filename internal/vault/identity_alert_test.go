package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newIdentityAlertServer(t *testing.T, disabled bool, lastUpdate time.Time) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/identity/entity/id":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"keys": []string{"ent-1"}},
			})
		case "/v1/identity/entity/id/ent-1":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"id":               "ent-1",
					"name":             "bob",
					"disabled":         disabled,
					"last_update_time": lastUpdate,
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestNewIdentityAlerter_NotNil(t *testing.T) {
	ts := newIdentityAlertServer(t, false, time.Now())
	defer ts.Close()
	c, _ := NewClient(ts.URL, "tok")
	s := NewIdentityScanner(c)
	a := NewIdentityAlerter(s, 0)
	if a == nil {
		t.Fatal("expected non-nil alerter")
	}
}

func TestNewIdentityAlerter_NilScanner(t *testing.T) {
	if NewIdentityAlerter(nil, 0) != nil {
		t.Fatal("expected nil for nil scanner")
	}
}

func TestIdentityAlerter_Evaluate_DisabledEntity(t *testing.T) {
	ts := newIdentityAlertServer(t, true, time.Now())
	defer ts.Close()
	c, _ := NewClient(ts.URL, "tok")
	a := NewIdentityAlerter(NewIdentityScanner(c), 30*24*time.Hour)
	alerts, err := a.Evaluate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Severity != SeverityWarning {
		t.Fatalf("expected warning severity, got %s", alerts[0].Severity)
	}
}

func TestIdentityAlerter_Evaluate_StaleEntity(t *testing.T) {
	old := time.Now().Add(-100 * 24 * time.Hour)
	ts := newIdentityAlertServer(t, false, old)
	defer ts.Close()
	c, _ := NewClient(ts.URL, "tok")
	a := NewIdentityAlerter(NewIdentityScanner(c), 30*24*time.Hour)
	alerts, err := a.Evaluate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for stale entity, got %d", len(alerts))
	}
}

func TestIdentityAlerter_Evaluate_NoAlert(t *testing.T) {
	ts := newIdentityAlertServer(t, false, time.Now())
	defer ts.Close()
	c, _ := NewClient(ts.URL, "tok")
	a := NewIdentityAlerter(NewIdentityScanner(c), 90*24*time.Hour)
	alerts, err := a.Evaluate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Fatalf("expected 0 alerts, got %d", len(alerts))
	}
}
