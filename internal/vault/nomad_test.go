package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newNomadTestServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/nomad/role", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"keys": []string{"deploy", "readonly"},
			},
		})
	})
	mux.HandleFunc("/v1/nomad/role/deploy", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"policies": []string{"deploy-policy"},
				"lease":    3600,
				"max_ttl":  7200,
				"global":   false,
				"type":     "client",
			},
		})
	})
	return httptest.NewServer(mux)
}

func TestNewNomadScanner_NotNil(t *testing.T) {
	client, _ := NewClient("http://localhost:8200", "token")
	s := NewNomadScanner(client, "")
	if s == nil {
		t.Fatal("expected non-nil NomadScanner")
	}
	if s.mount != "nomad" {
		t.Errorf("expected default mount 'nomad', got %s", s.mount)
	}
}

func TestNewNomadScanner_NilClient(t *testing.T) {
	s := NewNomadScanner(nil, "nomad")
	if s != nil {
		t.Fatal("expected nil NomadScanner for nil client")
	}
}

func TestNomadListRoles_Success(t *testing.T) {
	srv := newNomadTestServer()
	defer srv.Close()
	client, _ := NewClient(srv.URL, "test-token")
	s := NewNomadScanner(client, "nomad")
	roles, err := s.ListRoles()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(roles))
	}
}

func TestNomadGetRole_Success(t *testing.T) {
	srv := newNomadTestServer()
	defer srv.Close()
	client, _ := NewClient(srv.URL, "test-token")
	s := NewNomadScanner(client, "nomad")
	role, err := s.GetRole("deploy")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if role.Name != "deploy" {
		t.Errorf("expected name 'deploy', got %s", role.Name)
	}
	if role.LeaseTTL != 3600*time.Second {
		t.Errorf("expected LeaseTTL 3600s, got %v", role.LeaseTTL)
	}
	if role.IsExpired() {
		t.Error("expected role not expired")
	}
}

func TestNomadGetRole_EmptyName(t *testing.T) {
	client, _ := NewClient("http://localhost:8200", "token")
	s := NewNomadScanner(client, "nomad")
	_, err := s.GetRole("")
	if err == nil {
		t.Fatal("expected error for empty role name")
	}
}

func TestNomadRole_IsExpired_True(t *testing.T) {
	r := &NomadRole{LeaseTTL: 0}
	if !r.IsExpired() {
		t.Error("expected IsExpired true for zero TTL")
	}
}
