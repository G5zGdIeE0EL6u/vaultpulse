package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newMaintenanceTestServer(enabled bool, statusCode int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/maintenance" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(statusCode)
		if statusCode == http.StatusOK {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"maintenance_mode": enabled,
				"request_id":       "test-req-id",
			})
		}
	}))
}

func TestNewMaintenanceChecker_NotNil(t *testing.T) {
	c := &Client{}
	mc, err := NewMaintenanceChecker(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mc == nil {
		t.Fatal("expected non-nil MaintenanceChecker")
	}
}

func TestNewMaintenanceChecker_NilClient(t *testing.T) {
	_, err := NewMaintenanceChecker(nil)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestMaintenanceStatus_NotInMaintenance(t *testing.T) {
	srv := newMaintenanceTestServer(false, http.StatusOK)
	defer srv.Close()

	c, _ := NewClient(srv.URL, "test-token")
	mc, _ := NewMaintenanceChecker(c)

	status, err := mc.Status()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.IsInMaintenance() {
		t.Error("expected maintenance mode to be false")
	}
}

func TestMaintenanceStatus_InMaintenance(t *testing.T) {
	srv := newMaintenanceTestServer(true, http.StatusOK)
	defer srv.Close()

	c, _ := NewClient(srv.URL, "test-token")
	mc, _ := NewMaintenanceChecker(c)

	status, err := mc.Status()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !status.IsInMaintenance() {
		t.Error("expected maintenance mode to be true")
	}
}

func TestMaintenanceStatus_NonOK(t *testing.T) {
	srv := newMaintenanceTestServer(false, http.StatusInternalServerError)
	defer srv.Close()

	c, _ := NewClient(srv.URL, "test-token")
	mc, _ := NewMaintenanceChecker(c)

	_, err := mc.Status()
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
}
