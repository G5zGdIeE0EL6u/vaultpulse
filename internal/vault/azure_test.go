package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newAzureTestServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/azure/roles", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"keys": []string{"my-role"}},
		})
	})
	mux.HandleFunc("/v1/azure/roles/my-role", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"application_object_id": "obj-123",
				"ttl":     "48h",
				"max_ttl": "720h",
			},
		})
	})
	return httptest.NewServer(mux)
}

func TestNewAzureScanner_NotNil(t *testing.T) {
	s := NewAzureScanner(nil, "")
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
	if s.mount != "azure" {
		t.Errorf("expected default mount 'azure', got %s", s.mount)
	}
}

func TestNewAzureScanner_NilClient(t *testing.T) {
	s := NewAzureScanner(nil, "azure")
	_, err := s.ListRoles()
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestAzureListRoles_Success(t *testing.T) {
	srv := newAzureTestServer()
	defer srv.Close()
	client, _ := NewClient(srv.URL, "test-token")
	scanner := NewAzureScanner(client, "azure")
	roles, err := scanner.ListRoles()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roles) != 1 || roles[0] != "my-role" {
		t.Errorf("unexpected roles: %v", roles)
	}
}

func TestAzureGetRole_Success(t *testing.T) {
	srv := newAzureTestServer()
	defer srv.Close()
	client, _ := NewClient(srv.URL, "test-token")
	scanner := NewAzureScanner(client, "azure")
	role, err := scanner.GetRole("my-role")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if role.ApplicationObjectID != "obj-123" {
		t.Errorf("unexpected app object id: %s", role.ApplicationObjectID)
	}
}

func TestAzureGetRole_EmptyName(t *testing.T) {
	s := NewAzureScanner(nil, "azure")
	_, err := s.GetRole("")
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}
