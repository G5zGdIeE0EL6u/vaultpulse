package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newCertTestServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/pki/certs":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"keys": []string{"aa:bb:cc"}},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestNewCertScanner_NotNil(t *testing.T) {
	client := &Client{}
	s, err := NewCertScanner(client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
	if s.mount != "pki" {
		t.Errorf("expected default mount pki, got %s", s.mount)
	}
}

func TestNewCertScanner_NilClient(t *testing.T) {
	_, err := NewCertScanner(nil, "pki")
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestCertInfo_IsExpired_False(t *testing.T) {
	c := &CertInfo{Expiry: time.Now().Add(time.Hour)}
	if c.IsExpired() {
		t.Error("expected not expired")
	}
}

func TestCertInfo_IsExpired_True(t *testing.T) {
	c := &CertInfo{Expiry: time.Now().Add(-time.Hour)}
	if !c.IsExpired() {
		t.Error("expected expired")
	}
}

func TestCertInfo_TimeUntilExpiry_Positive(t *testing.T) {
	c := &CertInfo{Expiry: time.Now().Add(2 * time.Hour)}
	if c.TimeUntilExpiry() <= 0 {
		t.Error("expected positive duration")
	}
}
