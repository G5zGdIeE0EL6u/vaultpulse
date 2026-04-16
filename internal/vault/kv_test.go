package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newKVTestServer(t *testing.T, path string, status int, payload interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func TestNewKVReader_DefaultMount(t *testing.T) {
	client, _ := NewClient("http://127.0.0.1", "token")
	r := NewKVReader(client, "")
	if r.mount != "secret" {
		t.Fatalf("expected default mount 'secret', got %q", r.mount)
	}
}

func TestKVRead_EmptyPath(t *testing.T) {
	client, _ := NewClient("http://127.0.0.1", "token")
	r := NewKVReader(client, "secret")
	_, err := r.Read("")
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestKVRead_NotFound(t *testing.T) {
	srv := newKVTestServer(t, "/v1/secret/data/missing", http.StatusNotFound, nil)
	defer srv.Close()
	client, _ := NewClient(srv.URL, "token")
	r := NewKVReader(client, "secret")
	_, err := r.Read("missing")
	if err == nil {
		t.Fatal("expected not found error")
	}
}

func TestKVRead_Success(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"data": map[string]interface{}{"key": "value"},
			"metadata": map[string]interface{}{
				"created_time": "2024-01-01T00:00:00Z",
				"version":      float64(3),
			},
		},
	}
	srv := newKVTestServer(t, "/v1/secret/data/myapp/db", http.StatusOK, payload)
	defer srv.Close()
	client, _ := NewClient(srv.URL, "token")
	r := NewKVReader(client, "secret")
	secret, err := r.Read("myapp/db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret.Path != "myapp/db" {
		t.Errorf("expected path 'myapp/db', got %q", secret.Path)
	}
	if secret.Version != 3 {
		t.Errorf("expected version 3, got %d", secret.Version)
	}
	if secret.Data["key"] != "value" {
		t.Errorf("expected data key 'value'")
	}
}
