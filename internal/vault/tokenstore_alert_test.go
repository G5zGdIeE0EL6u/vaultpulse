package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTokenStoreAlertServer(t *testing.T, ttl int64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/token/accessors":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"keys": []string{"acc-alert"}},
			})
		case "/v1/auth/token/lookup-accessor":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"accessor":      "acc-alert",
					"creation_time": time.Now().Unix(),
					"ttl":           ttl,
					"display_name":  "alert-token",
					"policies":      []string{"default"},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestNewTokenStoreAlerter_NotNil(t *testing.T) {
	scanner, _ := NewTokenStoreScanner(&Client{})
	a, err := NewTokenStoreAlerter(scanner, DefaultTokenStoreThresholds())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a == nil {
		t.Fatal("expected non-nil alerter")
	}
}

func TestNewTokenStoreAlerter_NilScanner(t *testing.T) {
	_, err := NewTokenStoreAlerter(nil, DefaultTokenStoreThresholds())
	if err == nil {
		t.Fatal("expected error for nil scanner")
	}
}

func TestDefaultTokenStoreThresholds_NotEmpty(t *testing.T) {
	th := DefaultTokenStoreThresholds()
	if th.Warning == 0 || th.Critical == 0 {
		t.Fatal("expected non-zero default thresholds")
	}
	if th.Warning <= th.Critical {
		t.Fatal("warning threshold should be greater than critical")
	}
}

func TestTokenStoreAlerter_Evaluate_CriticalAlert(t *testing.T) {
	srv := newTokenStoreAlertServer(t, 600) // 10 minutes — below critical (12h)
	defer srv.Close()
	client, _ := NewClient(srv.URL, "test-token")
	scanner, _ := NewTokenStoreScanner(client)
	alerter, _ := NewTokenStoreAlerter(scanner, DefaultTokenStoreThresholds())
	alerts, err := alerter.Evaluate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Severity != SeverityCritical {
		t.Fatalf("expected critical severity, got %v", alerts[0].Severity)
	}
}

func TestTokenStoreAlerter_Evaluate_NoAlert(t *testing.T) {
	srv := newTokenStoreAlertServer(t, int64((72*time.Hour).Seconds())) // 72h — above warning
	defer srv.Close()
	client, _ := NewClient(srv.URL, "test-token")
	scanner, _ := NewTokenStoreScanner(client)
	alerter, _ := NewTokenStoreAlerter(scanner, DefaultTokenStoreThresholds())
	alerts, err := alerter.Evaluate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Fatalf("expected 0 alerts, got %d", len(alerts))
	}
}
