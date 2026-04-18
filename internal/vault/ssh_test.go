package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newSSHTestServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/ssh/roles":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"keys": []string{"my-role"}},
			})
		case "/v1/ssh/roles/my-role":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"key_type":      "ca",
					"ttl":           "5m",
					"max_ttl":       "30m",
					"allowed_users": "ubuntu",
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestNewSSHScanner_NotNil(t *testing.T) {
	srv := newSSHTestServer()
	defer srv.Close()
	c, _ := NewClient(srv.URL, "token")
	s, err := NewSSHScanner(c, "")
	if err != nil || s == nil {
		t.Fatal("expected non-nil scanner")
	}
}

func TestNewSSHScanner_NilClient(t *testing.T) {
	_, err := NewSSHScanner(nil, "ssh")
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestListRoles_Success(t *testing.T) {
	srv := newSSHTestServer()
	defer srv.Close()
	c, _ := NewClient(srv.URL, "token")
	s, _ := NewSSHScanner(c, "ssh")
	roles, err := s.ListRoles()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roles) != 1 || roles[0] != "my-role" {
		t.Fatalf("unexpected roles: %v", roles)
	}
}

func TestGetRole_Success(t *testing.T) {
	srv := newSSHTestServer()
	defer srv.Close()
	c, _ := NewClient(srv.URL, "token")
	s, _ := NewSSHScanner(c, "ssh")
	role, err := s.GetRole("my-role")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if role.KeyType != "ca" || role.AllowedUsers != "ubuntu" {
		t.Fatalf("unexpected role data: %+v", role)
	}
}

func TestSSHAlerter_Evaluate_RaisesAlerts(t *testing.T) {
	srv := newSSHTestServer()
	defer srv.Close()
	c, _ := NewClient(srv.URL, "token")
	s, _ := NewSSHScanner(c, "ssh")
	a, err := NewSSHAlerter(s, 10*time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	alerts, err := a.Evaluate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// my-role has TTL=5m < 10m and MaxTTL=30m < 1h → 2 alerts
	if len(alerts) != 2 {
		t.Fatalf("expected 2 alerts, got %d", len(alerts))
	}
}

func TestNewSSHAlerter_NilScanner(t *testing.T) {
	_, err := NewSSHAlerter(nil, 0, 0)
	if err == nil {
		t.Fatal("expected error for nil scanner")
	}
}
