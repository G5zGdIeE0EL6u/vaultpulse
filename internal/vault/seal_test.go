package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newSealTestServer(sealed bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/seal-status" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"sealed":       sealed,
			"initialized":  true,
			"progress":     0,
			"t":            3,
			"n":            5,
			"version":      "1.15.0",
			"cluster_name": "vault-cluster",
		})
	}))
}

func TestNewSealChecker_NotNil(t *testing.T) {
	svr := newSealTestServer(false)
	defer svr.Close()
	client, _ := NewClient(svr.URL, "test-token")
	checker, err := NewSealChecker(client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if checker == nil {
		t.Fatal("expected non-nil SealChecker")
	}
}

func TestNewSealChecker_NilClient(t *testing.T) {
	_, err := NewSealChecker(nil)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestSealStatus_Unsealed(t *testing.T) {
	svr := newSealTestServer(false)
	defer svr.Close()
	client, _ := NewClient(svr.URL, "test-token")
	checker, _ := NewSealChecker(client)

	status, err := checker.Status(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Sealed {
		t.Error("expected vault to be unsealed")
	}
	if !status.Initialized {
		t.Error("expected vault to be initialized")
	}
	if status.Version != "1.15.0" {
		t.Errorf("expected version 1.15.0, got %s", status.Version)
	}
	if status.ClusterName != "vault-cluster" {
		t.Errorf("expected cluster_name vault-cluster, got %s", status.ClusterName)
	}
	if status.Threshold != 3 {
		t.Errorf("expected threshold 3, got %d", status.Threshold)
	}
	if status.Shares != 5 {
		t.Errorf("expected shares 5, got %d", status.Shares)
	}
}

func TestSealStatus_Sealed(t *testing.T) {
	svr := newSealTestServer(true)
	defer svr.Close()
	client, _ := NewClient(svr.URL, "test-token")
	checker, _ := NewSealChecker(client)

	status, err := checker.Status(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !status.Sealed {
		t.Error("expected vault to be sealed")
	}
}
