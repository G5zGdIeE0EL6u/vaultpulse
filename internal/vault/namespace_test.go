package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newNamespaceTestServer(t *testing.T, keys []string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != "LIST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if keys == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		ikeys := make([]interface{}, len(keys))
		for i, k := range keys {
			ikeys[i] = k
		}
		resp := map[string]interface{}{"data": map[string]interface{}{"keys": ikeys}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
}

func TestNewNamespaceLister_NotNil(t *testing.T) {
	c, _ := NewClient("http://127.0.0.1:8200", "token")
	nl := NewNamespaceLister(c)
	if nl == nil {
		t.Fatal("expected non-nil NamespaceLister")
	}
}

func TestNamespaceLister_NilClient(t *testing.T) {
	nl := &NamespaceLister{client: nil}
	_, err := nl.List(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestNamespaceLister_EmptyResponse(t *testing.T) {
	srv := newNamespaceTestServer(t, []string{})
	defer srv.Close()

	c, err := NewClient(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	nl := NewNamespaceLister(c)
	results, err := nl.List(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

func TestNamespaceLister_ParsesKeys(t *testing.T) {
	srv := newNamespaceTestServer(t, []string{"team-a/", "team-b/"})
	defer srv.Close()

	c, err := NewClient(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	nl := NewNamespaceLister(c)
	results, err := nl.List(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].Path != "team-a" {
		t.Errorf("expected 'team-a', got %q", results[0].Path)
	}
}

func TestNamespaceLister_NotFound(t *testing.T) {
	// A nil keys slice causes the test server to return 404,
	// simulating a Vault instance with no namespaces configured.
	srv := newNamespaceTestServer(t, nil)
	defer srv.Close()

	c, err := NewClient(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	nl := NewNamespaceLister(c)
	_, err = nl.List(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for 404 response, got nil")
	}
}
