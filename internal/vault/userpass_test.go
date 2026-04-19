package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newUserpassTestServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/userpass/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"keys": []string{"alice", "bob"},
			},
		})
	})
	mux.HandleFunc("/v1/auth/userpass/users/alice", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"token_ttl":     float64(3600),
				"token_max_ttl": float64(86400),
			},
		})
	})
	return httptest.NewServer(mux)
}

func TestNewUserpassScanner_NotNil(t *testing.T) {
	srv := newUserpassTestServer()
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	s, err := NewUserpassScanner(c, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
}

func TestNewUserpassScanner_NilClient(t *testing.T) {
	_, err := NewUserpassScanner(nil, "userpass")
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestUserpassListUsers_Success(t *testing.T) {
	srv := newUserpassTestServer()
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	s, _ := NewUserpassScanner(c, "userpass")
	users, err := s.ListUsers()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
}

func TestUserpassGetUser_Success(t *testing.T) {
	srv := newUserpassTestServer()
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	s, _ := NewUserpassScanner(c, "userpass")
	role, err := s.GetUser("alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if role.Username != "alice" {
		t.Errorf("expected username alice, got %s", role.Username)
	}
	if role.TokenTTL.Seconds() != 3600 {
		t.Errorf("expected token_ttl 3600, got %v", role.TokenTTL.Seconds())
	}
}

func TestUserpassGetUser_EmptyUsername(t *testing.T) {
	srv := newUserpassTestServer()
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	s, _ := NewUserpassScanner(c, "userpass")
	_, err := s.GetUser("")
	if err == nil {
		t.Fatal("expected error for empty username")
	}
}
