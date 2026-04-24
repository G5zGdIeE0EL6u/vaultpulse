package vault

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newMetricsTestServer(statusCode int, body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte(body))
	}))
}

func TestNewMetricsCollector_NotNil(t *testing.T) {
	client, _ := NewClient("http://127.0.0.1:8200", "token")
	mc, err := NewMetricsCollector(client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mc == nil {
		t.Fatal("expected non-nil MetricsCollector")
	}
}

func TestNewMetricsCollector_NilClient(t *testing.T) {
	_, err := NewMetricsCollector(nil)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestCollect_Success(t *testing.T) {
	srv := newMetricsTestServer(http.StatusOK, "# vault metrics\n")
	defer srv.Close()

	client, _ := NewClient(srv.URL, "test-token")
	mc, _ := NewMetricsCollector(client)

	points, err := mc.Collect()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(points) == 0 {
		t.Fatal("expected at least one metric point")
	}
	if points[0].Name != "vault_up" {
		t.Errorf("expected vault_up, got %s", points[0].Name)
	}
}

func TestCollect_Non200(t *testing.T) {
	srv := newMetricsTestServer(http.StatusForbidden, "permission denied")
	defer srv.Close()

	client, _ := NewClient(srv.URL, "bad-token")
	mc, _ := NewMetricsCollector(client)

	_, err := mc.Collect()
	if err == nil {
		t.Fatal("expected error for non-200 response")
	}
}

func TestNewMetricsAlerter_NotNil(t *testing.T) {
	client, _ := NewClient("http://127.0.0.1:8200", "token")
	mc, _ := NewMetricsCollector(client)
	ma, err := NewMetricsAlerter(mc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ma == nil {
		t.Fatal("expected non-nil MetricsAlerter")
	}
}

func TestNewMetricsAlerter_NilCollector(t *testing.T) {
	_, err := NewMetricsAlerter(nil)
	if err == nil {
		t.Fatal("expected error for nil collector")
	}
}

func TestMetricsAlerter_Evaluate_Healthy(t *testing.T) {
	srv := newMetricsTestServer(http.StatusOK, "")
	defer srv.Close()

	client, _ := NewClient(srv.URL, "token")
	mc, _ := NewMetricsCollector(client)
	ma, _ := NewMetricsAlerter(mc)

	alert, err := ma.Evaluate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alert != nil {
		t.Errorf("expected no alert for healthy vault, got %+v", alert)
	}
}

func TestMetricsAlerter_Evaluate_CollectFails(t *testing.T) {
	srv := newMetricsTestServer(http.StatusInternalServerError, "error")
	defer srv.Close()

	client, _ := NewClient(srv.URL, "token")
	mc, _ := NewMetricsCollector(client)
	ma, _ := NewMetricsAlerter(mc)

	alert, err := ma.Evaluate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alert == nil {
		t.Fatal("expected alert when collection fails")
	}
	if alert.Severity != SeverityCritical {
		t.Errorf("expected critical severity, got %s", alert.Severity)
	}
}
