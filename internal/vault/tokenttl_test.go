package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTokenTTLTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/token/accessors":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"keys": []string{"acc-abc", "acc-xyz"}},
			})
		case "/v1/auth/token/lookup-accessor":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"accessor":     "acc-abc",
					"display_name": "test-token",
					"ttl":          float64(3600),
					"policies":     []string{"default"},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestNewTokenTTLScanner_NotNil(t *testing.T) {
	c, _ := NewClient("http://localhost", "token")
	s := NewTokenTTLScanner(c, "")
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
	if s.mount != "auth/token" {
		t.Errorf("expected default mount, got %s", s.mount)
	}
}

func TestNewTokenTTLScanner_NilClient(t *testing.T) {
	if NewTokenTTLScanner(nil, "") != nil {
		t.Fatal("expected nil for nil client")
	}
}

func TestTokenTTLEntry_IsExpired_False(t *testing.T) {
	e := &TokenTTLEntry{TTL: time.Hour}
	if e.IsExpired() {
		t.Error("expected not expired")
	}
}

func TestTokenTTLEntry_IsExpired_True(t *testing.T) {
	e := &TokenTTLEntry{TTL: 0}
	if !e.IsExpired() {
		t.Error("expected expired")
	}
}

func TestTokenTTLEntry_TimeUntilExpiry_Positive(t *testing.T) {
	e := &TokenTTLEntry{TTL: 2 * time.Hour}
	if e.TimeUntilExpiry() != 2*time.Hour {
		t.Errorf("unexpected TTL: %v", e.TimeUntilExpiry())
	}
}

func TestLookupAccessor_EmptyAccessor(t *testing.T) {
	c, _ := NewClient("http://localhost", "token")
	s := NewTokenTTLScanner(c, "")
	_, err := s.LookupAccessor("")
	if err == nil {
		t.Fatal("expected error for empty accessor")
	}
}
