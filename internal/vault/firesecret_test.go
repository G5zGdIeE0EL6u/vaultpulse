package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newFireSecretTestServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/secret/metadata" && r.URL.RawQuery == "list=true" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"keys": []string{"alpha", "beta"},
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

func TestNewFireSecretScanner_NotNil(t *testing.T) {
	c := &Client{Address: "http://localhost", Token: "tok", HTTP: &http.Client{}}
	s, err := NewFireSecretScanner(c, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
	if s.mount != "secret" {
		t.Errorf("expected default mount 'secret', got %q", s.mount)
	}
}

func TestNewFireSecretScanner_NilClient(t *testing.T) {
	_, err := NewFireSecretScanner(nil, "secret")
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestFireSecretListPaths_Success(t *testing.T) {
	srv := newFireSecretTestServer()
	defer srv.Close()
	c := &Client{Address: srv.URL, Token: "tok", HTTP: &http.Client{}}
	s, _ := NewFireSecretScanner(c, "secret")
	paths, err := s.ListPaths()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(paths) != 2 {
		t.Errorf("expected 2 paths, got %d", len(paths))
	}
}

func TestFireSecretEntry_IsExpired_False(t *testing.T) {
	e := &FireSecretEntry{ExpiresAt: time.Now().Add(10 * time.Minute)}
	if e.IsExpired() {
		t.Error("expected not expired")
	}
}

func TestFireSecretEntry_IsExpired_True(t *testing.T) {
	e := &FireSecretEntry{ExpiresAt: time.Now().Add(-1 * time.Minute)}
	if !e.IsExpired() {
		t.Error("expected expired")
	}
}

func TestNewFireSecretAlerter_NotNil(t *testing.T) {
	c := &Client{Address: "http://localhost", Token: "tok", HTTP: &http.Client{}}
	s, _ := NewFireSecretScanner(c, "secret")
	a, err := NewFireSecretAlerter(s, 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a == nil {
		t.Fatal("expected non-nil alerter")
	}
}

func TestFireSecretAlerter_Evaluate_CriticalAlert(t *testing.T) {
	c := &Client{Address: "http://localhost", Token: "tok", HTTP: &http.Client{}}
	s, _ := NewFireSecretScanner(c, "secret")
	a, _ := NewFireSecretAlerter(s, 72*time.Hour, 24*time.Hour)
	entry := &FireSecretEntry{
		Path:      "secret/mykey",
		Key:       "mykey",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	alert := a.Evaluate(entry)
	if alert == nil {
		t.Fatal("expected alert")
	}
	if alert.Severity != SeverityCritical {
		t.Errorf("expected critical, got %v", alert.Severity)
	}
}

func TestFireSecretAlerter_Evaluate_NoAlert(t *testing.T) {
	c := &Client{Address: "http://localhost", Token: "tok", HTTP: &http.Client{}}
	s, _ := NewFireSecretScanner(c, "secret")
	a, _ := NewFireSecretAlerter(s, 72*time.Hour, 24*time.Hour)
	entry := &FireSecretEntry{
		Path:      "secret/safe",
		Key:       "safe",
		ExpiresAt: time.Now().Add(168 * time.Hour),
	}
	if alert := a.Evaluate(entry); alert != nil {
		t.Errorf("expected no alert, got %v", alert)
	}
}
