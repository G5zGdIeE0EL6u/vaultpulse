package notify_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yourusername/vaultpulse/internal/notify"
)

func TestSend_Success(t *testing.T) {
	var received notify.WebhookPayload

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", ct)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("failed to decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := notify.NewWebhookNotifier(server.URL, 5*time.Second)
	payload := notify.WebhookPayload{
		Timestamp:  time.Now().UTC(),
		SecretPath: "secret/db/password",
		Severity:   "critical",
		Message:    "Secret expires in 1h",
		TTL:        3600,
	}

	if err := notifier.Send(payload); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if received.SecretPath != payload.SecretPath {
		t.Errorf("expected secret_path %q, got %q", payload.SecretPath, received.SecretPath)
	}
	if received.Severity != payload.Severity {
		t.Errorf("expected severity %q, got %q", payload.Severity, received.Severity)
	}
}

func TestSend_Non2xxStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	notifier := notify.NewWebhookNotifier(server.URL, 5*time.Second)
	err := notifier.Send(notify.WebhookPayload{})
	if err == nil {
		t.Fatal("expected error for non-2xx response, got nil")
	}
}

func TestSend_EmptyURL(t *testing.T) {
	notifier := notify.NewWebhookNotifier("", 5*time.Second)
	err := notifier.Send(notify.WebhookPayload{})
	if err == nil {
		t.Fatal("expected error for empty URL, got nil")
	}
}

func TestNewWebhookNotifier_DefaultTimeout(t *testing.T) {
	notifier := notify.NewWebhookNotifier("http://example.com", 0)
	if notifier.Timeout != 10*time.Second {
		t.Errorf("expected default timeout 10s, got %v", notifier.Timeout)
	}
}
