package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTokenStoreTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/token/accessors":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"keys": []string{"acc1", "acc2"}},
			})
		case "/v1/auth/token/lookup-accessor":
			now := time.Now()
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"accessor":      "acc1",
					"creation_time": now.Unix(),
					"ttl":           3600,
					"display_name":  "test-token",
					"policies":      []string{"default"},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestNewTokenStoreScanner_NotNil(t *testing.T) {
	s, err := NewTokenStoreScanner(&Client{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
}

func TestNewTokenStoreScanner_NilClient(t *testing.T) {
	_, err := NewTokenStoreScanner(nil)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestTokenStoreEntry_IsExpired_False(t *testing.T) {
	e := &TokenStoreEntry{TTL: 3600, ExpireTime: time.Now().Add(time.Hour)}
	if e.IsExpired() {
		t.Fatal("expected not expired")
	}
}

func TestTokenStoreEntry_IsExpired_True(t *testing.T) {
	e := &TokenStoreEntry{TTL: 1, ExpireTime: time.Now().Add(-time.Second)}
	if !e.IsExpired() {
		t.Fatal("expected expired")
	}
}

func TestTokenStoreEntry_TimeUntilExpiry_ZeroTTL(t *testing.T) {
	e := &TokenStoreEntry{TTL: 0}
	if e.TimeUntilExpiry() != 0 {
		t.Fatal("expected zero duration for zero TTL")
	}
}

func TestListAccessors_Success(t *testing.T) {
	srv := newTokenStoreTestServer(t)
	defer srv.Close()
	client, _ := NewClient(srv.URL, "test-token")
	scanner, _ := NewTokenStoreScanner(client)
	accessors, err := scanner.ListAccessors()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(accessors) != 2 {
		t.Fatalf("expected 2 accessors, got %d", len(accessors))
	}
}

func TestLookupAccessor_EmptyAccessor(t *testing.T) {
	client, _ := NewClient("http://localhost", "tok")
	scanner, _ := NewTokenStoreScanner(client)
	_, err := scanner.LookupAccessor("")
	if err == nil {
		t.Fatal("expected error for empty accessor")
	}
}

func TestLookupAccessor_Success(t *testing.T) {
	srv := newTokenStoreTestServer(t)
	defer srv.Close()
	client, _ := NewClient(srv.URL, "test-token")
	scanner, _ := NewTokenStoreScanner(client)
	entry, err := scanner.LookupAccessor("acc1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry.DisplayName != "test-token" {
		t.Fatalf("expected display_name 'test-token', got %q", entry.DisplayName)
	}
	if entry.TTL != 3600 {
		t.Fatalf("expected TTL 3600, got %d", entry.TTL)
	}
}
