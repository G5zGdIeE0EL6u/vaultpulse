package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTOTPTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/totp/keys":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"keys": []string{"mykey"}},
			})
		case "/v1/totp/keys/mykey":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"issuer":       "example.com",
					"account_name": "user@example.com",
					"period":       20,
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestNewTOTPScanner_NotNil(t *testing.T) {
	client := &Client{}
	s, err := NewTOTPScanner(client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
	if s.mount != "totp" {
		t.Errorf("expected default mount 'totp', got %q", s.mount)
	}
}

func TestNewTOTPScanner_NilClient(t *testing.T) {
	_, err := NewTOTPScanner(nil, "totp")
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestNewTOTPAlerter_NotNil(t *testing.T) {
	s, _ := NewTOTPScanner(&Client{}, "totp")
	a, err := NewTOTPAlerter(s, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a == nil {
		t.Fatal("expected non-nil alerter")
	}
	if a.minPeriod != 30 {
		t.Errorf("expected default minPeriod 30, got %d", a.minPeriod)
	}
}

func TestNewTOTPAlerter_NilScanner(t *testing.T) {
	_, err := NewTOTPAlerter(nil, 30)
	if err == nil {
		t.Fatal("expected error for nil scanner")
	}
}

func TestTOTPKey_IsExpired(t *testing.T) {
	k := &TOTPKey{Name: "test"}
	if k.IsExpired() {
		t.Error("TOTP keys should never be expired")
	}
}
