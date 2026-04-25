package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newACLTestServer(t *testing.T, accessor string, token *ACLToken, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/token/lookup-accessor" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		if status == http.StatusOK && token != nil {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": token})
		}
	}))
}

func TestNewACLScanner_NotNil(t *testing.T) {
	c, _ := NewClient("http://127.0.0.1:8200", "token")
	s := NewACLScanner(c)
	if s == nil {
		t.Fatal("expected non-nil ACLScanner")
	}
}

func TestNewACLScanner_NilClient(t *testing.T) {
	s := NewACLScanner(nil)
	if s != nil {
		t.Fatal("expected nil ACLScanner for nil client")
	}
}

func TestACLToken_IsExpired_False(t *testing.T) {
	tok := &ACLToken{ExpireTime: time.Now().Add(1 * time.Hour)}
	if tok.IsExpired() {
		t.Error("expected token to not be expired")
	}
}

func TestACLToken_IsExpired_True(t *testing.T) {
	tok := &ACLToken{ExpireTime: time.Now().Add(-1 * time.Hour)}
	if !tok.IsExpired() {
		t.Error("expected token to be expired")
	}
}

func TestACLToken_IsExpired_ZeroTime(t *testing.T) {
	tok := &ACLToken{}
	if tok.IsExpired() {
		t.Error("zero expire time should not be considered expired")
	}
}

func TestLookupAccessor_EmptyAccessor(t *testing.T) {
	c, _ := NewClient("http://127.0.0.1:8200", "token")
	s := NewACLScanner(c)
	_, err := s.LookupAccessor("")
	if err == nil {
		t.Fatal("expected error for empty accessor")
	}
}

func TestLookupAccessor_Success(t *testing.T) {
	expected := &ACLToken{
		Accessor:    "abc123",
		DisplayName: "test-token",
		Policies:    []string{"default"},
		ExpireTime:  time.Now().Add(24 * time.Hour),
	}
	srv := newACLTestServer(t, "abc123", expected, http.StatusOK)
	defer srv.Close()

	c, _ := NewClient(srv.URL, "test-token")
	s := NewACLScanner(c)
	tok, err := s.LookupAccessor("abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.Accessor != expected.Accessor {
		t.Errorf("expected accessor %q, got %q", expected.Accessor, tok.Accessor)
	}
}

func TestLookupAccessor_NotFound(t *testing.T) {
	srv := newACLTestServer(t, "", nil, http.StatusNotFound)
	defer srv.Close()

	c, _ := NewClient(srv.URL, "test-token")
	s := NewACLScanner(c)
	_, err := s.LookupAccessor("missing")
	if err == nil {
		t.Fatal("expected error for not-found accessor")
	}
}
