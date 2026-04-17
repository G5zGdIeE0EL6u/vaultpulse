package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newEnginesTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/mounts" {
			body := map[string]interface{}{
				"secret/": map[string]interface{}{
					"type":        "kv",
					"description": "key/value secrets",
					"accessor":    "kv_abc123",
					"options":     map[string]interface{}{},
					"config":      map[string]interface{}{},
				},
				"pki/": map[string]interface{}{
					"type":        "pki",
					"description": "pki secrets",
					"accessor":    "pki_xyz789",
					"options":     map[string]interface{}{},
					"config":      map[string]interface{}{},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(body)
			return
		}
		http.NotFound(w, r)
	}))
}

func TestNewEngineScanner_NotNil(t *testing.T) {
	client, _ := NewClient("http://127.0.0.1:8200", "token")
	scanner, err := NewEngineScanner(client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scanner == nil {
		t.Fatal("expected non-nil scanner")
	}
}

func TestNewEngineScanner_NilClient(t *testing.T) {
	_, err := NewEngineScanner(nil)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestListEngines_ReturnsMounts(t *testing.T) {
	server := newEnginesTestServer(t)
	defer server.Close()

	client, _ := NewClient(server.URL, "test-token")
	scanner, _ := NewEngineScanner(client)

	mounts, err := scanner.ListEngines()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mounts) != 2 {
		t.Fatalf("expected 2 mounts, got %d", len(mounts))
	}
}

func TestListEngines_TypesPresent(t *testing.T) {
	server := newEnginesTestServer(t)
	defer server.Close()

	client, _ := NewClient(server.URL, "test-token")
	scanner, _ := NewEngineScanner(client)

	mounts, err := scanner.ListEngines()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	types := map[string]bool{}
	for _, m := range mounts {
		types[m.Type] = true
	}
	if !types["kv"] || !types["pki"] {
		t.Error("expected kv and pki engine types")
	}
}
