package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newReplicationTestServer(status int, body interface{}) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

func TestNewReplicationChecker_NotNil(t *testing.T) {
	c, _ := NewClient("http://127.0.0.1:8200", "token")
	rc, err := NewReplicationChecker(c)
	if err != nil || rc == nil {
		t.Fatal("expected non-nil checker")
	}
}

func TestNewReplicationChecker_NilClient(t *testing.T) {
	_, err := NewReplicationChecker(nil)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestReplicationStatus_Success(t *testing.T) {
	body := map[string]interface{}{
		"data": map[string]interface{}{
			"dr": map[string]interface{}{
				"mode":    "primary",
				"primary": true,
				"last_wal": 42,
			},
			"performance": map[string]interface{}{
				"mode":    "secondary",
				"primary": false,
			},
			"connected": true,
		},
	}
	srv := newReplicationTestServer(http.StatusOK, body)
	defer srv.Close()

	c, _ := NewClient(srv.URL, "token")
	rc, _ := NewReplicationChecker(c)
	st, err := rc.Status()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st.DRMode != "primary" {
		t.Errorf("expected dr_mode primary, got %s", st.DRMode)
	}
	if !st.Connected {
		t.Error("expected connected true")
	}
	if st.LastWAL != 42 {
		t.Errorf("expected last_wal 42, got %d", st.LastWAL)
	}
}

func TestReplicationStatus_NonOK(t *testing.T) {
	srv := newReplicationTestServer(http.StatusForbidden, nil)
	defer srv.Close()

	c, _ := NewClient(srv.URL, "token")
	rc, _ := NewReplicationChecker(c)
	_, err := rc.Status()
	if err == nil {
		t.Fatal("expected error on non-200 response")
	}
}
