package vault

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newAgentTestServer(statusCode int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		w.Write([]byte(`{}`))
	}))
}

func TestNewAgentChecker_NotNil(t *testing.T) {
	c, _ := NewClient("http://127.0.0.1:8200", "test-token")
	ac, err := NewAgentChecker(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ac == nil {
		t.Fatal("expected non-nil AgentChecker")
	}
}

func TestNewAgentChecker_NilClient(t *testing.T) {
	_, err := NewAgentChecker(nil)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestNewAgentAlerter_NotNil(t *testing.T) {
	c, _ := NewClient("http://127.0.0.1:8200", "test-token")
	ac, _ := NewAgentChecker(c)
	aa, err := NewAgentAlerter(ac)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if aa == nil {
		t.Fatal("expected non-nil AgentAlerter")
	}
}

func TestNewAgentAlerter_NilChecker(t *testing.T) {
	_, err := NewAgentAlerter(nil)
	if err == nil {
		t.Fatal("expected error for nil checker")
	}
}

func TestAgentAlerter_Evaluate_NotRunning(t *testing.T) {
	svr := newAgentTestServer(http.StatusInternalServerError)
	defer svr.Close()

	c, _ := NewClient(svr.URL, "test-token")
	ac, _ := NewAgentChecker(c)
	aa, _ := NewAgentAlerter(ac)

	alerts, err := aa.Evaluate(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) == 0 {
		t.Fatal("expected at least one alert for non-running agent")
	}
	if alerts[0].Severity != "critical" {
		t.Errorf("expected critical severity, got %s", alerts[0].Severity)
	}
}

func TestAgentAlerter_Evaluate_Running(t *testing.T) {
	svr := newAgentTestServer(http.StatusOK)
	defer svr.Close()

	c, _ := NewClient(svr.URL, "test-token")
	ac, _ := NewAgentChecker(c)
	aa, _ := NewAgentAlerter(ac)

	alerts, err := aa.Evaluate(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected no alerts for running agent, got %d", len(alerts))
	}
}
