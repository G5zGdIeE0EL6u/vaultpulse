package notify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewPagerDutyNotifier_DefaultTimeout(t *testing.T) {
	n := NewPagerDutyNotifier("test-key", 0)
	if n.client.Timeout != 10*time.Second {
		t.Errorf("expected default timeout 10s, got %v", n.client.Timeout)
	}
}

func TestNewPagerDutyNotifier_CustomTimeout(t *testing.T) {
	n := NewPagerDutyNotifier("test-key", 5*time.Second)
	if n.client.Timeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %v", n.client.Timeout)
	}
}

func TestPagerDutySend_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		var payload pagerDutyPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		if payload.EventAction != "trigger" {
			t.Errorf("expected event_action 'trigger', got %s", payload.EventAction)
		}
		if payload.Payload.Severity != "critical" {
			t.Errorf("expected severity 'critical', got %s", payload.Payload.Severity)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ts.Close()

	n := NewPagerDutyNotifier("fake-key", 5*time.Second)
	// Override the URL by temporarily replacing the constant via a test-friendly approach.
	n.client.Transport = redirectTransport(ts.URL)

	err := n.Send("Vault secret expiring soon", "vaultpulse", "critical")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestPagerDutySend_Non2xxStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	n := NewPagerDutyNotifier("fake-key", 5*time.Second)
	n.client.Transport = redirectTransport(ts.URL)

	err := n.Send("summary", "source", "warning")
	if err == nil {
		t.Error("expected error for non-2xx status, got nil")
	}
}

func TestPagerDutySend_EmptyKey(t *testing.T) {
	n := NewPagerDutyNotifier("", 5*time.Second)
	err := n.Send("summary", "source", "info")
	if err == nil {
		t.Error("expected error for empty integration key, got nil")
	}
}

// redirectTransport rewrites all requests to the given base URL (for testing).
type redirectTransport string

func (rt redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Host = string(rt)[7:] // strip "http://"
	req.URL.Scheme = "http"
	return http.DefaultTransport.RoundTrip(req)
}
