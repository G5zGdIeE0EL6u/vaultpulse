package vault

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newScannerTestServer(t *testing.T, ttl int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/sys/health":
			w.WriteHeader(http.StatusOK)
		case "/v1/secret/data/expiring":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"data":{"data":{"key":"val"},"metadata":{}},"lease_duration":%d,"renewable":true}`, ttl)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestScanner_ScanReturnsResults(t *testing.T) {
	srv := newScannerTestServer(t, 60)
	defer srv.Close()

	client, err := NewClient(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	monitor := NewMonitor(5*time.Minute, 10*time.Minute)
	scanner := NewScanner(client, monitor, []string{"secret/data/expiring"})

	results := scanner.Scan(context.Background())
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Err != nil {
		t.Errorf("unexpected error: %v", results[0].Err)
	}
	if results[0].Path != "secret/data/expiring" {
		t.Errorf("unexpected path: %s", results[0].Path)
	}
}

func TestScanner_ScanErrorPath(t *testing.T) {
	srv := newScannerTestServer(t, 60)
	defer srv.Close()

	client, err := NewClient(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	monitor := NewMonitor(5*time.Minute, 10*time.Minute)
	scanner := NewScanner(client, monitor, []string{"secret/data/nonexistent"})

	results := scanner.Scan(context.Background())
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Err == nil {
		t.Error("expected error for nonexistent path, got nil")
	}
}

func TestAlerts_FiltersNilAlerts(t *testing.T) {
	results := []ScanResult{
		{Path: "a", Alert: nil},
		{Path: "b", Alert: &Alert{Path: "b"}},
		{Path: "c", Alert: nil},
	}

	alerts := Alerts(results)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Path != "b" {
		t.Errorf("unexpected alert path: %s", alerts[0].Path)
	}
}

func TestNewScanner_NotNil(t *testing.T) {
	client, _ := NewClient("http://localhost:8200", "token")
	monitor := NewMonitor(5*time.Minute, 10*time.Minute)
	scanner := NewScanner(client, monitor, []string{})
	if scanner == nil {
		t.Fatal("expected non-nil scanner")
	}
}
