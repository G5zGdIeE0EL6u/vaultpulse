package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newAppRoleTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/approle/role":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"keys": []string{"my-role"}},
			})
		case "/v1/auth/approle/role/my-role":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"role_id":       "abc-123",
					"secret_id_ttl": float64((10 * time.Hour).Nanoseconds()),
					"token_ttl":     float64((1 * time.Hour).Nanoseconds()),
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestNewAppRoleScanner_NotNil(t *testing.T) {
	srv := newAppRoleTestServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	s, err := NewAppRoleScanner(c, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
	if s.mount != "auth/approle" {
		t.Errorf("expected default mount, got %q", s.mount)
	}
}

func TestNewAppRoleScanner_NilClient(t *testing.T) {
	_, err := NewAppRoleScanner(nil, "")
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestAppRoleListRoles_Success(t *testing.T) {
	srv := newAppRoleTestServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	s, _ := NewAppRoleScanner(c, "auth/approle")
	roles, err := s.ListRoles()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roles) == 0 {
		t.Fatal("expected at least one role")
	}
}

func TestNewAppRoleAlerter_NotNil(t *testing.T) {
	srv := newAppRoleTestServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	s, _ := NewAppRoleScanner(c, "")
	a, err := NewAppRoleAlerter(s, 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a == nil {
		t.Fatal("expected non-nil alerter")
	}
}

func TestNewAppRoleAlerter_NilScanner(t *testing.T) {
	_, err := NewAppRoleAlerter(nil, 0, 0)
	if err == nil {
		t.Fatal("expected error for nil scanner")
	}
}
