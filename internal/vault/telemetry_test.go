package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTelemetryTestServer(counters []map[string]interface{}) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/metrics" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"Counters": counters})
	}))
}

func TestNewTelemetryCollector_NotNil(t *testing.T) {
	c := &Client{}
	tc, err := NewTelemetryCollector(c)
	if err != nil || tc == nil {
		t.Fatalf("expected non-nil collector, got err=%v", err)
	}
}

func TestNewTelemetryCollector_NilClient(t *testing.T) {
	_, err := NewTelemetryCollector(nil)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestTelemetryCollect_Success(t *testing.T) {
	counters := []map[string]interface{}{
		{"Name": "vault.expire.num_leases", "Count": 120},
		{"Name": "vault.token.count", "Count": 300},
		{"Name": "vault.core.handle_error", "Count": 5},
	}
	srv := newTelemetryTestServer(counters)
	defer srv.Close()

	c := &Client{Address: srv.URL, HTTP: srv.Client()}
	tc, _ := NewTelemetryCollector(c)
	sample, err := tc.Collect()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sample.LeaseCount != 120 {
		t.Errorf("expected LeaseCount=120, got %d", sample.LeaseCount)
	}
	if sample.TokenCount != 300 {
		t.Errorf("expected TokenCount=300, got %d", sample.TokenCount)
	}
	if sample.ErrorCount != 5 {
		t.Errorf("expected ErrorCount=5, got %d", sample.ErrorCount)
	}
}

func TestTelemetryCollect_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c := &Client{Address: srv.URL, HTTP: srv.Client()}
	tc, _ := NewTelemetryCollector(c)
	_, err := tc.Collect()
	if err == nil {
		t.Fatal("expected error for non-200 response")
	}
}

func TestTelemetryAlerter_Evaluate_RaisesAlert(t *testing.T) {
	counters := []map[string]interface{}{
		{"Name": "vault.expire.num_leases", "Count": 99999},
	}
	srv := newTelemetryTestServer(counters)
	defer srv.Close()

	c := &Client{Address: srv.URL, HTTP: srv.Client()}
	tc, _ := NewTelemetryCollector(c)
	ta, err := NewTelemetryAlerter(tc, DefaultTelemetryThresholds())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	alerts, err := ta.Evaluate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) == 0 {
		t.Error("expected at least one alert for high lease count")
	}
}

func TestTelemetryAlerter_Evaluate_NoAlert(t *testing.T) {
	counters := []map[string]interface{}{
		{"Name": "vault.expire.num_leases", "Count": 10},
	}
	srv := newTelemetryTestServer(counters)
	defer srv.Close()

	c := &Client{Address: srv.URL, HTTP: srv.Client()}
	tc, _ := NewTelemetryCollector(c)
	ta, _ := NewTelemetryAlerter(tc, DefaultTelemetryThresholds())
	alerts, err := ta.Evaluate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(alerts))
	}
}
