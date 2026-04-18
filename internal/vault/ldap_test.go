package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newLDAPTestServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/ldap/groups", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"keys": []string{"admins", "devs"}},
		})
	})
	mux.HandleFunc("/v1/auth/ldap/groups/admins", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"ttl": float64(3600), "max_ttl": float64(7200)},
		})
	})
	mux.HandleFunc("/v1/auth/ldap/groups/devs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"ttl": float64(0)},
		})
	})
	return httptest.NewServer(mux)
}

func TestNewLDAPScanner_NotNil(t *testing.T) {
	c := &Client{}
	s, err := NewLDAPScanner(c, "")
	if err != nil || s == nil {
		t.Fatal("expected non-nil scanner")
	}
	if s.mount != "ldap" {
		t.Errorf("expected default mount 'ldap', got %q", s.mount)
	}
}

func TestNewLDAPScanner_NilClient(t *testing.T) {
	_, err := NewLDAPScanner(nil, "")
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestLDAPListRoles_Success(t *testing.T) {
	srv := newLDAPTestServer()
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	s, _ := NewLDAPScanner(c, "ldap")
	names, err := s.ListRoles()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(names) == 0 {
		t.Error("expected at least one role")
	}
}

func TestLDAPGetRole_Success(t *testing.T) {
	srv := newLDAPTestServer()
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	s, _ := NewLDAPScanner(c, "ldap")
	role, err := s.GetRole("admins")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if role.TTL == 0 {
		t.Error("expected non-zero TTL")
	}
}

func TestLDAPGetRole_EmptyName(t *testing.T) {
	c := &Client{}
	s, _ := NewLDAPScanner(c, "ldap")
	_, err := s.GetRole("")
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}
