package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newAuthTestServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "s.testtoken",
					"lease_duration": 3600,
					"renewable":      true,
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

func TestNewAuthenticator_NotNil(t *testing.T) {
	srv := newAuthTestServer()
	defer srv.Close()
	client, _ := NewClient(srv.URL, "test-token")
	auth, err := NewAuthenticator(client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if auth == nil {
		t.Fatal("expected non-nil authenticator")
	}
}

func TestNewAuthenticator_NilClient(t *testing.T) {
	_, err := NewAuthenticator(nil)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestAuthenticate_TokenMethod(t *testing.T) {
	srv := newAuthTestServer()
	defer srv.Close()
	client, _ := NewClient(srv.URL, "test-token")
	auth, _ := NewAuthenticator(client)
	info, err := auth.Authenticate(context.Background(), AuthenticatorConfig{
		Method: AuthToken,
		Token:  "mytoken",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Token != "mytoken" {
		t.Errorf("expected token 'mytoken', got %s", info.Token)
	}
}

func TestAuthenticate_TokenMethod_Empty(t *testing.T) {
	srv := newAuthTestServer()
	defer srv.Close()
	client, _ := NewClient(srv.URL, "test-token")
	auth, _ := NewAuthenticator(client)
	_, err := auth.Authenticate(context.Background(), AuthenticatorConfig{Method: AuthToken})
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestAuthenticate_AppRole_Success(t *testing.T) {
	srv := newAuthTestServer()
	defer srv.Close()
	client, _ := NewClient(srv.URL, "test-token")
	auth, _ := NewAuthenticator(client)
	info, err := auth.Authenticate(context.Background(), AuthenticatorConfig{
		Method:   AuthAppRole,
		RoleID:   "role-id",
		SecretID: "secret-id",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Token != "s.testtoken" {
		t.Errorf("expected token 's.testtoken', got %s", info.Token)
	}
	if info.LeaseTTL != 3600*time.Second {
		t.Errorf("unexpected lease TTL: %v", info.LeaseTTL)
	}
}

func TestAuthenticate_UnsupportedMethod(t *testing.T) {
	srv := newAuthTestServer()
	defer srv.Close()
	client, _ := NewClient(srv.URL, "test-token")
	auth, _ := NewAuthenticator(client)
	_, err := auth.Authenticate(context.Background(), AuthenticatorConfig{Method: "ldap"})
	if err == nil {
		t.Fatal("expected error for unsupported method")
	}
}

func TestAuthInfo_IsExpired(t *testing.T) {
	expired := &AuthInfo{LeaseTTL: 0}
	if !expired.IsExpired() {
		t.Error("expected expired")
	}
	active := &AuthInfo{LeaseTTL: time.Hour}
	if active.IsExpired() {
		t.Error("expected not expired")
	}
}
