package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newMFATestServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/identity/mfa/method":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"keys": []string{"method-totp-1"},
				},
			})
		case "/v1/identity/mfa/method/method-totp-1":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"id":             "method-totp-1",
					"name":           "corp-totp",
					"type":           "totp",
					"mount_accessor": "auth_userpass_abc123",
				},
			})
		case "/v1/identity/mfa/method/not-found":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestNewMFAScanner_NotNil(t *testing.T) {
	ts := newMFATestServer()
	defer ts.Close()
	c, _ := NewClient(ts.URL, "test-token")
	s, err := NewMFAScanner(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
}

func TestNewMFAScanner_NilClient(t *testing.T) {
	_, err := NewMFAScanner(nil)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestMFAListMethods_Success(t *testing.T) {
	ts := newMFATestServer()
	defer ts.Close()
	c, _ := NewClient(ts.URL, "test-token")
	s, _ := NewMFAScanner(c)

	methods, err := s.ListMethods()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(methods) != 1 {
		t.Fatalf("expected 1 method, got %d", len(methods))
	}
	if methods[0].Name != "corp-totp" {
		t.Errorf("expected name 'corp-totp', got %q", methods[0].Name)
	}
	if methods[0].Type != "totp" {
		t.Errorf("expected type 'totp', got %q", methods[0].Type)
	}
}

func TestMFAGetMethod_Success(t *testing.T) {
	ts := newMFATestServer()
	defer ts.Close()
	c, _ := NewClient(ts.URL, "test-token")
	s, _ := NewMFAScanner(c)

	m, err := s.GetMethod("method-totp-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.ID != "method-totp-1" {
		t.Errorf("expected id 'method-totp-1', got %q", m.ID)
	}
}

func TestMFAGetMethod_EmptyID(t *testing.T) {
	ts := newMFATestServer()
	defer ts.Close()
	c, _ := NewClient(ts.URL, "test-token")
	s, _ := NewMFAScanner(c)

	_, err := s.GetMethod("")
	if err == nil {
		t.Fatal("expected error for empty id")
	}
}

func TestMFAGetMethod_NotFound(t *testing.T) {
	ts := newMFATestServer()
	defer ts.Close()
	c, _ := NewClient(ts.URL, "test-token")
	s, _ := NewMFAScanner(c)

	_, err := s.GetMethod("not-found")
	if err == nil {
		t.Fatal("expected error for not-found method")
	}
}
