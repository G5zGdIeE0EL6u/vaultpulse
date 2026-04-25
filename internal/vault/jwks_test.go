package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newJWKSTestServer(keys []map[string]string, status int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": keys})
	}))
}

func TestNewJWKSScanner_NotNil(t *testing.T) {
	c, _ := NewClient("http://localhost", "token")
	s := NewJWKSScanner(c)
	if s == nil {
		t.Fatal("expected non-nil JWKSScanner")
	}
}

func TestNewJWKSScanner_NilClient(t *testing.T) {
	s := NewJWKSScanner(nil)
	if s != nil {
		t.Fatal("expected nil JWKSScanner for nil client")
	}
}

func TestJWKSListKeys_Success(t *testing.T) {
	keys := []map[string]string{
		{"kid": "key-1", "alg": "RS256", "kty": "RSA", "use": "sig"},
	}
	srv := newJWKSTestServer(keys, http.StatusOK)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "token")
	s := NewJWKSScanner(c)
	result, err := s.ListKeys("jwt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 key, got %d", len(result))
	}
	if result[0].KeyID != "key-1" {
		t.Errorf("expected kid=key-1, got %s", result[0].KeyID)
	}
}

func TestJWKSListKeys_NonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c, _ := NewClient(srv.URL, "token")
	s := NewJWKSScanner(c)
	_, err := s.ListKeys("jwt")
	if err == nil {
		t.Fatal("expected error for non-200 response")
	}
}

func TestNewJWKSAlerter_NotNil(t *testing.T) {
	c, _ := NewClient("http://localhost", "token")
	s := NewJWKSScanner(c)
	a := NewJWKSAlerter(s)
	if a == nil {
		t.Fatal("expected non-nil JWKSAlerter")
	}
}

func TestNewJWKSAlerter_NilScanner(t *testing.T) {
	a := NewJWKSAlerter(nil)
	if a != nil {
		t.Fatal("expected nil JWKSAlerter for nil scanner")
	}
}

func TestJWKSKey_IsExpired_False(t *testing.T) {
	k := JWKSKey{ExpiresAt: time.Now().Add(time.Hour)}
	if k.IsExpired() {
		t.Error("key should not be expired")
	}
}

func TestJWKSKey_IsExpired_True(t *testing.T) {
	k := JWKSKey{ExpiresAt: time.Now().Add(-time.Hour)}
	if !k.IsExpired() {
		t.Error("key should be expired")
	}
}
