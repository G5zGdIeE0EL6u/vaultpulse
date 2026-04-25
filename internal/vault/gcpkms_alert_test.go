package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newGCPKMSAlertServer(overdueKey bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/gcpkms/keys":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"keys": []string{"k1"}},
			})
		case "/v1/gcpkms/keys/k1":
			lastRotated := time.Now().Add(-2 * time.Hour)
			if overdueKey {
				lastRotated = time.Now().Add(-72 * time.Hour)
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"rotation_period": int64(86400),
					"last_rotated":    lastRotated,
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestNewGCPKMSAlerter_NotNil(t *testing.T) {
	srv := newGCPKMSAlertServer(false)
	defer srv.Close()
	client, _ := NewClient(srv.URL, "token")
	scanner, _ := NewGCPKMSScanner(client, "gcpkms")
	alerter, err := NewGCPKMSAlerter(scanner, 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alerter == nil {
		t.Fatal("expected non-nil alerter")
	}
}

func TestNewGCPKMSAlerter_NilScanner(t *testing.T) {
	_, err := NewGCPKMSAlerter(nil, 0, 0)
	if err == nil {
		t.Fatal("expected error for nil scanner")
	}
}

func TestGCPKMSAlerter_Evaluate_NoAlert(t *testing.T) {
	srv := newGCPKMSAlertServer(false)
	defer srv.Close()
	client, _ := NewClient(srv.URL, "token")
	scanner, _ := NewGCPKMSScanner(client, "gcpkms")
	alerter, _ := NewGCPKMSAlerter(scanner, 7*24*time.Hour, 24*time.Hour)
	alerts, err := alerter.Evaluate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(alerts))
	}
}

func TestGCPKMSAlerter_Evaluate_CriticalAlert(t *testing.T) {
	srv := newGCPKMSAlertServer(true)
	defer srv.Close()
	client, _ := NewClient(srv.URL, "token")
	scanner, _ := NewGCPKMSScanner(client, "gcpkms")
	alerter, _ := NewGCPKMSAlerter(scanner, 7*24*time.Hour, 24*time.Hour)
	alerts, err := alerter.Evaluate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) == 0 {
		t.Fatal("expected at least one alert")
	}
	if alerts[0].Severity != SeverityCritical {
		t.Errorf("expected critical severity, got %v", alerts[0].Severity)
	}
}
