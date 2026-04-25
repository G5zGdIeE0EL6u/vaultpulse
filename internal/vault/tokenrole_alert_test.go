package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTokenRoleAlertServer(t *testing.T, explicitMaxTTL int64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/token/roles":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"keys": []string{"expiring-role"}},
			})
		case "/v1/auth/token/roles/expiring-role":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"explicit_max_ttl": explicitMaxTTL,
					"renewable":        true,
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestNewTokenRoleAlerter_NotNil(t *testing.T) {
	srv := newTokenRoleAlertServer(t, 3600)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "tok")
	s, _ := NewTokenRoleScanner(c)
	a, err := NewTokenRoleAlerter(s, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a == nil {
		t.Fatal("expected non-nil alerter")
	}
}

func TestNewTokenRoleAlerter_NilScanner(t *testing.T) {
	_, err := NewTokenRoleAlerter(nil, nil)
	if err == nil {
		t.Fatal("expected error for nil scanner")
	}
}

func TestNewTokenRoleAlerter_DefaultThresholds(t *testing.T) {
	srv := newTokenRoleAlertServer(t, 3600)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "tok")
	s, _ := NewTokenRoleScanner(c)
	a, _ := NewTokenRoleAlerter(s, nil)
	if a.thresholds["warning"] != 72*time.Hour {
		t.Errorf("expected default warning threshold 72h, got %v", a.thresholds["warning"])
	}
}

func TestTokenRoleAlerter_Evaluate_CriticalAlert(t *testing.T) {
	// 1 hour explicit_max_ttl — below critical threshold of 24h
	srv := newTokenRoleAlertServer(t, 3600)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "tok")
	s, _ := NewTokenRoleScanner(c)
	a, _ := NewTokenRoleAlerter(s, nil)
	alerts, err := a.Evaluate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Severity != SeverityCritical {
		t.Errorf("expected critical severity, got %s", alerts[0].Severity)
	}
}

func TestTokenRoleAlerter_Evaluate_NoAlertForZeroTTL(t *testing.T) {
	// 0 explicit_max_ttl means no expiry — should produce no alert
	srv := newTokenRoleAlertServer(t, 0)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "tok")
	s, _ := NewTokenRoleScanner(c)
	a, _ := NewTokenRoleAlerter(s, nil)
	alerts, err := a.Evaluate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts, got %d", len(alerts))
	}
}
