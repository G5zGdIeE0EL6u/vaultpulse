package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newRabbitMQTestServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/rabbitmq/roles", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"keys": []string{"read-only", "admin"},
			},
		})
	})
	mux.HandleFunc("/v1/rabbitmq/roles/read-only", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"vhosts": `{"/":{"read":".*","write":"","configure":""}}`,
				"tags":   "",
				"ttl":    json.Number("3600"),
				"max_ttl": json.Number("86400"),
			},
		})
	})
	return httptest.NewServer(mux)
}

func TestNewRabbitMQScanner_NotNil(t *testing.T) {
	s, err := NewRabbitMQScanner(&Client{}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
	if s.mount != "rabbitmq" {
		t.Errorf("expected default mount 'rabbitmq', got %s", s.mount)
	}
}

func TestNewRabbitMQScanner_NilClient(t *testing.T) {
	_, err := NewRabbitMQScanner(nil, "rabbitmq")
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestRabbitMQListRoles_Success(t *testing.T) {
	srv := newRabbitMQTestServer()
	defer srv.Close()

	client, err := NewClient(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	scanner, _ := NewRabbitMQScanner(client, "rabbitmq")
	roles, err := scanner.ListRoles()
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if len(roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(roles))
	}
}

func TestRabbitMQRole_IsExpired_False(t *testing.T) {
	role := &RabbitMQRole{
		Name:      "read-only",
		TTL:       3600 * 1e9,
		CreatedAt: timeNow(),
	}
	if role.IsExpired() {
		t.Error("expected role not to be expired")
	}
}

func TestRabbitMQRole_IsExpired_True(t *testing.T) {
	role := &RabbitMQRole{
		Name:      "old-role",
		TTL:       1,
		CreatedAt: timeNow().Add(-10),
	}
	if !role.IsExpired() {
		t.Error("expected role to be expired")
	}
}

func TestRabbitMQRole_TimeUntilExpiry_ZeroTTL(t *testing.T) {
	role := &RabbitMQRole{Name: "no-ttl", TTL: 0}
	if role.TimeUntilExpiry() != 0 {
		t.Error("expected zero duration for zero TTL")
	}
}
