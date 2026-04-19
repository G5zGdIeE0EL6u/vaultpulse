package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newGCPTestServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/gcp/roles", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"keys": []string{"my-role"},
			},
		})
	})
	mux.HandleFunc("/v1/gcp/roles/my-role", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"secret_type":   "access_token",
				"token_ttl":     3600,
				"token_max_ttl": 7200,
			},
		})
	})
	return httptest.NewServer(mux)
}

func TestNewGCPScanner_NotNil(t *testing.T) {
	client, _ := NewClient("http://localhost:8200", "token")
	s, err := NewGCPScanner(client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
}

func TestNewGCPScanner_NilClient(t *testing.T) {
	_, err := NewGCPScanner(nil, "gcp")
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestGCPListRoles_Success(t *testing.T) {
	srv := newGCPTestServer()
	defer srv.Close()
	client, _ := NewClient(srv.URL, "test-token")
	scanner, _ := NewGCPScanner(client, "gcp")
	roles, err := scanner.ListRoles()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roles) == 0 {
		t.Fatal("expected at least one role")
	}
}

func TestGCPGetRole_Success(t *testing.T) {
	srv := newGCPTestServer()
	defer srv.Close()
	client, _ := NewClient(srv.URL, "test-token")
	scanner, _ := NewGCPScanner(client, "gcp")
	role, err := scanner.GetRole("my-role")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if role.Name != "my-role" {
		t.Errorf("expected name 'my-role', got %q", role.Name)
	}
}

func TestGCPGetRole_EmptyName(t *testing.T) {
	client, _ := NewClient("http://localhost:8200", "token")
	scanner, _ := NewGCPScanner(client, "gcp")
	_, err := scanner.GetRole("")
	if err == nil {
		t.Fatal("expected error for empty role name")
	}
}
