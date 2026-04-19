package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newKubernetesTestServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/kubernetes/role", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"keys": []string{"my-role", "dev-role"}},
		})
	})
	mux.HandleFunc("/v1/auth/kubernetes/role/my-role", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"bound_service_account_names":      []string{"default"},
				"bound_service_account_namespaces": []string{"default"},
				"ttl":     3600,
				"max_ttl": 7200,
			},
		})
	})
	return httptest.NewServer(mux)
}

func TestNewKubernetesScanner_NotNil(t *testing.T) {
	c, _ := NewClient("http://localhost:8200", "token")
	s := NewKubernetesScanner(c, "")
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
	if s.mount != "kubernetes" {
		t.Errorf("expected default mount 'kubernetes', got %s", s.mount)
	}
}

func TestNewKubernetesScanner_NilClient(t *testing.T) {
	s := NewKubernetesScanner(nil, "k8s")
	if s == nil {
		t.Fatal("expected non-nil scanner even with nil client")
	}
}

func TestKubernetesListRoles_Success(t *testing.T) {
	srv := newKubernetesTestServer()
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	s := NewKubernetesScanner(c, "kubernetes")
	roles, err := s.ListRoles()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(roles))
	}
}

func TestKubernetesGetRole_Success(t *testing.T) {
	srv := newKubernetesTestServer()
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	s := NewKubernetesScanner(c, "kubernetes")
	role, err := s.GetRole("my-role")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if role.Name != "my-role" {
		t.Errorf("expected name 'my-role', got %s", role.Name)
	}
}

func TestKubernetesGetRole_EmptyName(t *testing.T) {
	c, _ := NewClient("http://localhost:8200", "token")
	s := NewKubernetesScanner(c, "kubernetes")
	_, err := s.GetRole("")
	if err == nil {
		t.Fatal("expected error for empty role name")
	}
}
