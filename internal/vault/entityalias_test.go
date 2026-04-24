package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newEntityAliasTestServer(t *testing.T, status int, payload interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func TestNewEntityAliasScanner_NotNil(t *testing.T) {
	client, _ := NewClient("http://127.0.0.1:8200", "test-token")
	scanner, err := NewEntityAliasScanner(client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scanner == nil {
		t.Fatal("expected non-nil scanner")
	}
}

func TestNewEntityAliasScanner_NilClient(t *testing.T) {
	_, err := NewEntityAliasScanner(nil)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestListAliases_Success(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"key_info": map[string]interface{}{
				"alias-id-1": map[string]interface{}{
					"name":       "alice",
					"mount_type": "userpass",
					"mount_path": "auth/userpass/",
				},
				"alias-id-2": map[string]interface{}{
					"name":       "bob",
					"mount_type": "ldap",
					"mount_path": "auth/ldap/",
				},
			},
		},
	}
	svr := newEntityAliasTestServer(t, http.StatusOK, payload)
	defer svr.Close()

	client, _ := NewClient(svr.URL, "test-token")
	scanner, _ := NewEntityAliasScanner(client)

	aliases, err := scanner.ListAliases()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(aliases) != 2 {
		t.Fatalf("expected 2 aliases, got %d", len(aliases))
	}
}

func TestListAliases_NonOK(t *testing.T) {
	svr := newEntityAliasTestServer(t, http.StatusForbidden, nil)
	defer svr.Close()

	client, _ := NewClient(svr.URL, "test-token")
	scanner, _ := NewEntityAliasScanner(client)

	_, err := scanner.ListAliases()
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
}

func TestListAliases_IDPropagated(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"key_info": map[string]interface{}{
				"unique-alias-id": map[string]interface{}{
					"name":       "charlie",
					"mount_type": "github",
					"mount_path": "auth/github/",
				},
			},
		},
	}
	svr := newEntityAliasTestServer(t, http.StatusOK, payload)
	defer svr.Close()

	client, _ := NewClient(svr.URL, "test-token")
	scanner, _ := NewEntityAliasScanner(client)

	aliases, err := scanner.ListAliases()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(aliases) != 1 {
		t.Fatalf("expected 1 alias, got %d", len(aliases))
	}
	if aliases[0].ID != "unique-alias-id" {
		t.Errorf("expected ID 'unique-alias-id', got %q", aliases[0].ID)
	}
}
