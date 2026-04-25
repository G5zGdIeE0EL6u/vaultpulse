package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newSecretStoreTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/secret/metadata/apps":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"keys": []string{"db-password", "api-key"},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestNewSecretStoreScanner_NotNil(t *testing.T) {
	client := &Client{}
	s := NewSecretStoreScanner(client, "secret")
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
}

func TestNewSecretStoreScanner_DefaultMount(t *testing.T) {
	s := NewSecretStoreScanner(&Client{}, "")
	if s.mount != "secret" {
		t.Fatalf("expected default mount 'secret', got %q", s.mount)
	}
}

func TestSecretStoreEntry_IsExpired_False(t *testing.T) {
	e := &SecretStoreEntry{ExpiresAt: time.Now().Add(time.Hour)}
	if e.IsExpired() {
		t.Fatal("expected not expired")
	}
}

func TestSecretStoreEntry_IsExpired_True(t *testing.T) {
	e := &SecretStoreEntry{ExpiresAt: time.Now().Add(-time.Hour)}
	if !e.IsExpired() {
		t.Fatal("expected expired")
	}
}

func TestSecretStoreEntry_TTL_Positive(t *testing.T) {
	e := &SecretStoreEntry{ExpiresAt: time.Now().Add(2 * time.Hour)}
	if e.TTL() <= 0 {
		t.Fatal("expected positive TTL")
	}
}

func TestListEntries_Success(t *testing.T) {
	srv := newSecretStoreTestServer(t)
	defer srv.Close()
	client, _ := NewClient(srv.URL, "test-token")
	scanner := NewSecretStoreScanner(client, "secret")
	entries, err := scanner.ListEntries("apps")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
}
