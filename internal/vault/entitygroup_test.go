package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newEntityGroupTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/identity/group/id":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"keys": []string{"group-abc", "group-def"},
				},
			})
		case "/v1/identity/group/id/group-abc":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"id":               "group-abc",
					"name":             "admins",
					"type":             "internal",
					"disabled":         false,
					"creation_time":    time.Now().Add(-72 * time.Hour),
					"last_update_time": time.Now().Add(-1 * time.Hour),
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestNewEntityGroupScanner_NotNil(t *testing.T) {
	c, _ := NewClient("http://127.0.0.1:8200", "token")
	s := NewEntityGroupScanner(c)
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
}

func TestNewEntityGroupScanner_NilClient(t *testing.T) {
	s := NewEntityGroupScanner(nil)
	if s != nil {
		t.Fatal("expected nil scanner for nil client")
	}
}

func TestEntityGroupListGroups_Success(t *testing.T) {
	srv := newEntityGroupTestServer(t)
	defer srv.Close()

	c, _ := NewClient(srv.URL, "test-token")
	s := NewEntityGroupScanner(c)

	keys, err := s.ListGroups()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
}

func TestEntityGroupGetGroup_Success(t *testing.T) {
	srv := newEntityGroupTestServer(t)
	defer srv.Close()

	c, _ := NewClient(srv.URL, "test-token")
	s := NewEntityGroupScanner(c)

	g, err := s.GetGroup("group-abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.Name != "admins" {
		t.Errorf("expected name 'admins', got %q", g.Name)
	}
}

func TestEntityGroupGetGroup_EmptyID(t *testing.T) {
	c, _ := NewClient("http://127.0.0.1:8200", "token")
	s := NewEntityGroupScanner(c)

	_, err := s.GetGroup("")
	if err == nil {
		t.Fatal("expected error for empty id")
	}
}

func TestEntityGroup_IsDisabled(t *testing.T) {
	g := &EntityGroup{Disabled: true}
	if !g.IsDisabled() {
		t.Error("expected group to be disabled")
	}
	g.Disabled = false
	if g.IsDisabled() {
		t.Error("expected group to not be disabled")
	}
}
