package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newSnapshotTestServer(t *testing.T, statusCode int, payload map[string]interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": payload})
	}))
}

func TestNewSnapshotManager_NotNil(t *testing.T) {
	srv := newMockVaultServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	sm, err := NewSnapshotManager(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sm == nil {
		t.Fatal("expected non-nil SnapshotManager")
	}
}

func TestNewSnapshotManager_NilClient(t *testing.T) {
	_, err := NewSnapshotManager(nil)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestSnapshotTake_Success(t *testing.T) {
	srv := newSnapshotTestServer(t, http.StatusOK, map[string]interface{}{"size": float64(4096)})
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	sm, _ := NewSnapshotManager(c)
	info, err := sm.Take(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("expected non-nil SnapshotInfo")
	}
	if info.TakenAt.IsZero() {
		t.Error("expected TakenAt to be set")
	}
}

func TestSnapshotTake_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	sm, _ := NewSnapshotManager(c)
	_, err := sm.Take(context.Background())
	if err == nil {
		t.Fatal("expected error for empty/failed response")
	}
}
