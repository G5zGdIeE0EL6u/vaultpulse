package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newHATestServer(status HAStatus, statusCode int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(status)
	}))
}

func TestNewHAChecker_NotNil(t *testing.T) {
	client, _ := NewClient("http://127.0.0.1:8200", "test-token")
	checker, err := NewHAChecker(client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if checker == nil {
		t.Fatal("expected non-nil HAChecker")
	}
}

func TestNewHAChecker_NilClient(t *testing.T) {
	_, err := NewHAChecker(nil)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestHAStatus_LeaderNode(t *testing.T) {
	expected := HAStatus{
		Enabled:     true,
		Leader:      true,
		LeaderAddr:  "http://vault-0:8200",
		ClusterName: "vault-cluster",
		ClusterID:   "abc-123",
	}
	ts := newHATestServer(expected, http.StatusOK)
	defer ts.Close()

	client, _ := NewClient(ts.URL, "test-token")
	checker, _ := NewHAChecker(client)
	status, err := checker.Status()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !status.Enabled {
		t.Error("expected HA to be enabled")
	}
	if !status.Leader {
		t.Error("expected node to be leader")
	}
	if status.LeaderAddr != expected.LeaderAddr {
		t.Errorf("expected leader addr %s, got %s", expected.LeaderAddr, status.LeaderAddr)
	}
}

func TestHAStatus_NonOK(t *testing.T) {
	ts := newHATestServer(HAStatus{}, http.StatusServiceUnavailable)
	defer ts.Close()

	client, _ := NewClient(ts.URL, "test-token")
	checker, _ := NewHAChecker(client)
	_, err := checker.Status()
	if err == nil {
		t.Fatal("expected error for non-200 response")
	}
}

func TestNewHAAlerter_NotNil(t *testing.T) {
	client, _ := NewClient("http://127.0.0.1:8200", "test-token")
	checker, _ := NewHAChecker(client)
	alerter, err := NewHAAlerter(checker)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alerter == nil {
		t.Fatal("expected non-nil HAAlterter")
	}
}

func TestHAAlerter_Evaluate_NoLeader(t *testing.T) {
	status := HAStatus{Enabled: true, Leader: false, LeaderAddr: ""}
	ts := newHATestServer(status, http.StatusOK)
	defer ts.Close()

	client, _ := NewClient(ts.URL, "test-token")
	checker, _ := NewHAChecker(client)
	alerter, _ := NewHAAlerter(checker)

	alerts, err := alerter.Evaluate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) == 0 {
		t.Fatal("expected at least one alert")
	}
	if alerts[0].Severity != HASeverityCritical {
		t.Errorf("expected critical severity, got %s", alerts[0].Severity)
	}
}

func TestHAAlerter_Evaluate_StandaloneMode(t *testing.T) {
	status := HAStatus{Enabled: false}
	ts := newHATestServer(status, http.StatusOK)
	defer ts.Close()

	client, _ := NewClient(ts.URL, "test-token")
	checker, _ := NewHAChecker(client)
	alerter, _ := NewHAAlerter(checker)

	alerts, err := alerter.Evaluate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 || alerts[0].Severity != HASeverityWarning {
		t.Errorf("expected single warning alert for standalone mode")
	}
}
