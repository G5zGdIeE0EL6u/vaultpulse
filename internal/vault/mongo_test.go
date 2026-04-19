package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newMongoTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/database/roles":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"keys": []string{"mongo-app"}},
			})
		case "/v1/database/roles/mongo-app":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"default_ttl": float64(3600), "max_ttl": float64(86400)},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestNewMongoScanner_NotNil(t *testing.T) {
	srv := newMongoTestServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	s, err := NewMongoScanner(c, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
}

func TestNewMongoScanner_NilClient(t *testing.T) {
	_, err := NewMongoScanner(nil, "database")
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestMongoListRoles_Success(t *testing.T) {
	srv := newMongoTestServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	s, _ := NewMongoScanner(c, "database")
	roles, err := s.ListRoles()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roles) == 0 {
		t.Fatal("expected at least one role")
	}
}

func TestMongoGetRole_Success(t *testing.T) {
	srv := newMongoTestServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	s, _ := NewMongoScanner(c, "database")
	role, err := s.GetRole("mongo-app")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if role.MaxTTL != 86400*time.Second {
		t.Errorf("expected MaxTTL 86400s, got %s", role.MaxTTL)
	}
}

func TestNewMongoAlerter_NotNil(t *testing.T) {
	srv := newMongoTestServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	s, _ := NewMongoScanner(c, "database")
	a, err := NewMongoAlerter(s, 0, 0)
	if err != nil || a == nil {
		t.Fatal("expected non-nil alerter")
	}
}

func TestNewMongoAlerter_NilScanner(t *testing.T) {
	_, err := NewMongoAlerter(nil, time.Hour, time.Minute)
	if err == nil {
		t.Fatal("expected error for nil scanner")
	}
}
