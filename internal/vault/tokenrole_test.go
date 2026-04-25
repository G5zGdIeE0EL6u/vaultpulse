package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTokenRoleTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/token/roles":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"keys": []string{"read-only", "admin"}},
			})
		case "/v1/auth/token/roles/read-only":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"explicit_max_ttl": 3600,
					"token_ttl":        1800,
					"token_max_ttl":    3600,
					"renewable":        true,
					"orphan":           false,
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestNewTokenRoleScanner_NotNil(t *testing.T) {
	srv := newTokenRoleTestServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	s, err := NewTokenRoleScanner(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
}

func TestNewTokenRoleScanner_NilClient(t *testing.T) {
	_, err := NewTokenRoleScanner(nil)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestTokenRoleListRoles_Success(t *testing.T) {
	srv := newTokenRoleTestServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	s, _ := NewTokenRoleScanner(c)
	roles, err := s.ListRoles()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roles) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(roles))
	}
}

func TestTokenRoleGetRole_Success(t *testing.T) {
	srv := newTokenRoleTestServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	s, _ := NewTokenRoleScanner(c)
	role, err := s.GetRole("read-only")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if role.Name != "read-only" {
		t.Errorf("expected name read-only, got %s", role.Name)
	}
	if role.TokenTTL != 1800*time.Second {
		t.Errorf("unexpected token TTL: %v", role.TokenTTL)
	}
}

func TestTokenRoleGetRole_EmptyName(t *testing.T) {
	srv := newTokenRoleTestServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	s, _ := NewTokenRoleScanner(c)
	_, err := s.GetRole("")
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}
