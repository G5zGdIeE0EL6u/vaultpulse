package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newIdentityTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/identity/entity/id":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"keys": []string{"id-1", "id-2"}},
			})
		case "/v1/identity/entity/id/id-1":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"id":               "id-1",
					"name":             "alice",
					"disabled":         false,
					"last_update_time": time.Now().Add(-10 * 24 * time.Hour),
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestNewIdentityScanner_NotNil(t *testing.T) {
	ts := newIdentityTestServer(t)
	defer ts.Close()
	c, _ := NewClient(ts.URL, "tok")
	s := NewIdentityScanner(c)
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
}

func TestNewIdentityScanner_NilClient(t *testing.T) {
	if NewIdentityScanner(nil) != nil {
		t.Fatal("expected nil for nil client")
	}
}

func TestIdentityListEntities_Success(t *testing.T) {
	ts := newIdentityTestServer(t)
	defer ts.Close()
	c, _ := NewClient(ts.URL, "tok")
	s := NewIdentityScanner(c)
	ids, err := s.ListEntities()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 ids, got %d", len(ids))
	}
}

func TestIdentityGetEntity_EmptyID(t *testing.T) {
	ts := newIdentityTestServer(t)
	defer ts.Close()
	c, _ := NewClient(ts.URL, "tok")
	s := NewIdentityScanner(c)
	_, err := s.GetEntity("")
	if err == nil {
		t.Fatal("expected error for empty id")
	}
}

func TestIdentityGetEntity_Success(t *testing.T) {
	ts := newIdentityTestServer(t)
	defer ts.Close()
	c, _ := NewClient(ts.URL, "tok")
	s := NewIdentityScanner(c)
	entity, err := s.GetEntity("id-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entity.Name != "alice" {
		t.Fatalf("expected alice, got %s", entity.Name)
	}
}
