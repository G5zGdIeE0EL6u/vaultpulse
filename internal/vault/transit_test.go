package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTransitTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/transit/keys":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"keys": []string{"my-key", "other-key"}},
			})
		case "/v1/transit/keys/my-key":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"type":             "aes256-gcm96",
					"deletion_allowed": false,
					"exportable":       true,
					"latest_version":   3,
				},
			})
		case "/v1/transit/keys/missing":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestNewTransitScanner_NotNil(t *testing.T) {
	c := &Client{}
	ts := NewTransitScanner(c, "")
	if ts == nil {
		t.Fatal("expected non-nil TransitScanner")
	}
	if ts.mount != "transit" {
		t.Errorf("expected default mount 'transit', got %q", ts.mount)
	}
}

func TestNewTransitScanner_NilClient(t *testing.T) {
	ts := NewTransitScanner(nil, "transit")
	_, err := ts.ListKeys(context.Background())
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestListKeys_Success(t *testing.T) {
	srv := newTransitTestServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	ts := NewTransitScanner(c, "transit")
	keys, err := ts.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}
}

func TestGetKey_Success(t *testing.T) {
	srv := newTransitTestServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	ts := NewTransitScanner(c, "transit")
	key, err := ts.GetKey(context.Background(), "my-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key.Type != "aes256-gcm96" {
		t.Errorf("expected aes256-gcm96, got %q", key.Type)
	}
	if key.LatestVersion != 3 {
		t.Errorf("expected version 3, got %d", key.LatestVersion)
	}
}

func TestGetKey_NotFound(t *testing.T) {
	srv := newTransitTestServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	ts := NewTransitScanner(c, "transit")
	_, err := ts.GetKey(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestGetKey_EmptyName(t *testing.T) {
	c := &Client{}
	ts := NewTransitScanner(c, "transit")
	_, err := ts.GetKey(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty key name")
	}
}
