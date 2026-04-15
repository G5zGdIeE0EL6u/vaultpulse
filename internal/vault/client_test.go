package vault_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vaultpulse/vaultpulse/internal/vault"
)

func newMockVaultServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func TestNewClient_Success(t *testing.T) {
	srv := newMockVaultServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	client, err := vault.NewClient(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestIsHealthy_Healthy(t *testing.T) {
	srv := newMockVaultServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"initialized":true,"sealed":false,"standby":false}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))

	client, err := vault.NewClient(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	healthy, err := client.IsHealthy()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !healthy {
		t.Error("expected vault to be healthy")
	}
}

func TestReadSecret_NotFound(t *testing.T) {
	srv := newMockVaultServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{}`))
	}))

	client, err := vault.NewClient(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	_, err = client.ReadSecret("secret/data/missing")
	if err == nil {
		t.Fatal("expected error for missing secret, got nil")
	}
}
