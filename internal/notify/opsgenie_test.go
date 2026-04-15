package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewOpsGenieNotifier_DefaultTimeout(t *testing.T) {
	n := NewOpsGenieNotifier("test-key", 0)
	if n.client.Timeout != 10*time.Second {
		t.Errorf("expected default timeout 10s, got %v", n.client.Timeout)
	}
}

func TestNewOpsGenieNotifier_CustomTimeout(t *testing.T) {
	n := NewOpsGenieNotifier("test-key", 5*time.Second)
	if n.client.Timeout != 5*time.Second {
		t.Errorf("expected 5s timeout, got %v", n.client.Timeout)
	}
}

func TestOpsGenieSend_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Error("expected Authorization header")
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	n := NewOpsGenieNotifier("test-key", 5*time.Second)
	n.apiURL = server.URL

	err := n.Send(context.Background(), Alert{
		SecretPath: "secret/db",
		Message:    "expires soon",
		Severity:   "critical",
	})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestOpsGenieSend_Non2xxStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	n := NewOpsGenieNotifier("test-key", 5*time.Second)
	n.apiURL = server.URL

	err := n.Send(context.Background(), Alert{SecretPath: "secret/db", Severity: "warning"})
	if err == nil {
		t.Error("expected error for non-2xx status")
	}
}

func TestOpsGenieSend_EmptyKey(t *testing.T) {
	n := NewOpsGenieNotifier("", 5*time.Second)
	err := n.Send(context.Background(), Alert{SecretPath: "secret/db"})
	if err == nil {
		t.Error("expected error for empty api key")
	}
}

func TestPriorityFromSeverity(t *testing.T) {
	cases := []struct {
		severity string
		want     string
	}{
		{"critical", "P1"},
		{"warning", "P3"},
		{"info", "P5"},
		{"", "P5"},
	}
	for _, c := range cases {
		got := priorityFromSeverity(c.severity)
		if got != c.want {
			t.Errorf("priorityFromSeverity(%q) = %q, want %q", c.severity, got, c.want)
		}
	}
}
