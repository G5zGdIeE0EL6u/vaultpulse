package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newConsulTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/consul/roles":
			json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"keys": []string{"myrole"}}})
		case "/v1/consul/roles/myrole":
			json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"lease": "72h", "token_type": "client", "policies": []interface{}{"read"}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestNewConsulScanner_NotNil(t *testing.T) {
	c := &Client{}
	s := NewConsulScanner(c, "")
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
	if s.mount != "consul" {
		t.Errorf("expected default mount 'consul', got %q", s.mount)
	}
}

func TestNewConsulScanner_NilClient(t *testing.T) {
	if NewConsulScanner(nil, "") != nil {
		t.Fatal("expected nil for nil client")
	}
}

func TestConsulListRoles_Success(t *testing.T) {
	srv := newConsulTestServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	s := NewConsulScanner(c, "consul")
	roles, err := s.ListRoles()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roles) != 1 || roles[0] != "myrole" {
		t.Errorf("unexpected roles: %v", roles)
	}
}

func TestConsulGetRole_Success(t *testing.T) {
	srv := newConsulTestServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	s := NewConsulScanner(c, "consul")
	role, err := s.GetRole("myrole")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if role.Lease != 72*time.Hour {
		t.Errorf("expected 72h lease, got %v", role.Lease)
	}
	if role.TokenType != "client" {
		t.Errorf("expected token_type 'client', got %q", role.TokenType)
	}
}

func TestNewConsulAlerter_NotNil(t *testing.T) {
	s := NewConsulScanner(&Client{}, "")
	a := NewConsulAlerter(s, 0, 0)
	if a == nil {
		t.Fatal("expected non-nil alerter")
	}
}

func TestNewConsulAlerter_NilScanner(t *testing.T) {
	if NewConsulAlerter(nil, 0, 0) != nil {
		t.Fatal("expected nil for nil scanner")
	}
}
