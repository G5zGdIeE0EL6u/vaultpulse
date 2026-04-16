package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newPolicyTestServer(t *testing.T, name string, payload interface{}, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func TestNewPolicyChecker_NotNil(t *testing.T) {
	srv := newMockVaultServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	pc := NewPolicyChecker(c)
	if pc == nil {
		t.Fatal("expected non-nil PolicyChecker")
	}
}

func TestGetPolicy_EmptyName(t *testing.T) {
	srv := newMockVaultServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	pc := NewPolicyChecker(c)
	_, err := pc.GetPolicy(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty policy name")
	}
}

func TestGetPolicy_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	pc := NewPolicyChecker(c)
	_, err := pc.GetPolicy(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected error for missing policy")
	}
}

func TestExtractPaths_Valid(t *testing.T) {
	data := map[string]interface{}{
		"paths": []interface{}{"secret/data/foo", "secret/data/bar"},
	}
	paths := extractPaths(data)
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(paths))
	}
}

func TestExtractPaths_Missing(t *testing.T) {
	paths := extractPaths(map[string]interface{}{})
	if paths != nil {
		t.Fatal("expected nil paths for missing key")
	}
}
