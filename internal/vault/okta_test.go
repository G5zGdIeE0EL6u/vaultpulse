package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newOktaTestServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/okta/users", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"keys": []string{"alice", "bob"}},
		})
	})
	mux.HandleFunc("/v1/auth/okta/users/alice", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"policies": []interface{}{"default"},
				"groups":   []interface{}{"dev"},
				"ttl":      "48h",
			},
		})
	})
	mux.HandleFunc("/v1/auth/okta/users/bob", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	return httptest.NewServer(mux)
}

func TestNewOktaScanner_NotNil(t *testing.T) {
	c := &Client{}
	s := NewOktaScanner(c, "")
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
	if s.mount != "okta" {
		t.Errorf("expected default mount 'okta', got %q", s.mount)
	}
}

func TestNewOktaScanner_NilClient(t *testing.T) {
	if NewOktaScanner(nil, "okta") != nil {
		t.Fatal("expected nil for nil client")
	}
}

func TestOktaUser_IsExpired_False(t *testing.T) {
	u := &OktaUser{TTL: time.Hour}
	if u.IsExpired() {
		t.Error("expected not expired")
	}
}

func TestOktaUser_IsExpired_True(t *testing.T) {
	u := &OktaUser{TTL: 0}
	if !u.IsExpired() {
		t.Error("expected expired")
	}
}

func TestOktaGetUser_EmptyUsername(t *testing.T) {
	s := &OktaScanner{client: &Client{}, mount: "okta"}
	_, err := s.GetUser("")
	if err == nil {
		t.Fatal("expected error for empty username")
	}
}
