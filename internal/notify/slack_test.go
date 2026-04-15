package notify

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewSlackNotifier_DefaultTimeout(t *testing.T) {
	n := NewSlackNotifier("https://hooks.slack.com/test", 0)
	if n == nil {
		t.Fatal("expected non-nil SlackNotifier")
	}
	if n.client.Timeout != 10*time.Second {
		t.Errorf("expected default timeout 10s, got %v", n.client.Timeout)
	}
}

func TestSlackSend_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", ct)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	n := NewSlackNotifier(server.URL, 5*time.Second)
	if err := n.Send("secret/myapp is expiring soon", "warning"); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestSlackSend_Non2xxStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	n := NewSlackNotifier(server.URL, 5*time.Second)
	err := n.Send("some alert", "critical")
	if err == nil {
		t.Fatal("expected error for non-2xx response")
	}
}

func TestSlackSend_EmptyURL(t *testing.T) {
	n := NewSlackNotifier("", 5*time.Second)
	err := n.Send("some alert", "warning")
	if err == nil {
		t.Fatal("expected error for empty webhook URL")
	}
}

func TestColorForSeverity(t *testing.T) {
	tests := []struct {
		severity string
		expected string
	}{
		{"critical", "#FF0000"},
		{"warning", "#FFA500"},
		{"info", "#36a64f"},
		{"", "#36a64f"},
	}
	for _, tc := range tests {
		got := colorForSeverity(tc.severity)
		if got != tc.expected {
			t.Errorf("colorForSeverity(%q) = %q, want %q", tc.severity, got, tc.expected)
		}
	}
}
