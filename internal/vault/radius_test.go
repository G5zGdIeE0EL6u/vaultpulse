package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newRADIUSTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/radius/users":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"keys": []string{"alice", "bob"}},
			})
		case "/v1/auth/radius/users/alice":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"policies": []string{"default", "dev"}},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestNewRADIUSScanner_NotNil(t *testing.T) {
	ts := newRADIUSTestServer(t)
	defer ts.Close()
	client, _ := NewClient(ts.URL, "test-token")
	scanner, err := NewRADIUSScanner(client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scanner == nil {
		t.Fatal("expected non-nil scanner")
	}
}

func TestNewRADIUSScanner_NilClient(t *testing.T) {
	_, err := NewRADIUSScanner(nil, "radius")
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestRADIUSListUsers_Success(t *testing.T) {
	ts := newRADIUSTestServer(t)
	defer ts.Close()
	client, _ := NewClient(ts.URL, "test-token")
	scanner, _ := NewRADIUSScanner(client, "radius")
	users, err := scanner.ListUsers()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
}

func TestRADIUSGetUser_Success(t *testing.T) {
	ts := newRADIUSTestServer(t)
	defer ts.Close()
	client, _ := NewClient(ts.URL, "test-token")
	scanner, _ := NewRADIUSScanner(client, "radius")
	user, err := scanner.GetUser("alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.Username != "alice" {
		t.Errorf("expected username alice, got %s", user.Username)
	}
	if len(user.Policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(user.Policies))
	}
}

func TestRADIUSGetUser_EmptyUsername(t *testing.T) {
	ts := newRADIUSTestServer(t)
	defer ts.Close()
	client, _ := NewClient(ts.URL, "test-token")
	scanner, _ := NewRADIUSScanner(client, "radius")
	_, err := scanner.GetUser("")
	if err == nil {
		t.Fatal("expected error for empty username")
	}
}
