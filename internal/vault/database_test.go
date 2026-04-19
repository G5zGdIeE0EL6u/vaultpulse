package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newDatabaseTestServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/database/roles", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"keys": []string{"readonly", "readwrite"},
			},
		})
	})
	mux.HandleFunc("/v1/database/roles/readonly", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"default_ttl":          3600,
				"max_ttl":              86400,
				"creation_statements": []string{"CREATE USER ..."},
			},
		})
	})
	mux.HandleFunc("/v1/database/roles/missing", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	return httptest.NewServer(mux)
}

func TestNewDatabaseScanner_NotNil(t *testing.T) {
	client, _ := NewClient("http://localhost:8200", "token")
	s, err := NewDatabaseScanner(client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
	if s.mount != "database" {
		t.Errorf("expected default mount 'database', got %q", s.mount)
	}
}

func TestNewDatabaseScanner_NilClient(t *testing.T) {
	_, err := NewDatabaseScanner(nil, "database")
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestDatabaseListRoles_Success(t *testing.T) {
	srv := newDatabaseTestServer()
	defer srv.Close()
	client, _ := NewClient(srv.URL, "token")
	scanner, _ := NewDatabaseScanner(client, "database")
	roles, err := scanner.ListRoles()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(roles))
	}
}

func TestDatabaseGetRole_Success(t *testing.T) {
	srv := newDatabaseTestServer()
	defer srv.Close()
	client, _ := NewClient(srv.URL, "token")
	scanner, _ := NewDatabaseScanner(client, "database")
	role, err := scanner.GetRole("readonly")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if role.Name != "readonly" {
		t.Errorf("expected name 'readonly', got %q", role.Name)
	}
	if role.DefaultTTL.Seconds() != 3600 {
		t.Errorf("expected default TTL 3600s, got %v", role.DefaultTTL)
	}
}

func TestDatabaseGetRole_NotFound(t *testing.T) {
	srv := newDatabaseTestServer()
	defer srv.Close()
	client, _ := NewClient(srv.URL, "token")
	scanner, _ := NewDatabaseScanner(client, "database")
	_, err := scanner.GetRole("missing")
	if err == nil {
		t.Fatal("expected error for missing role")
	}
}

func TestDatabaseGetRole_EmptyName(t *testing.T) {
	client, _ := NewClient("http://localhost:8200", "token")
	scanner, _ := NewDatabaseScanner(client, "database")
	_, err := scanner.GetRole("")
	if err == nil {
		t.Fatal("expected error for empty role name")
	}
}
