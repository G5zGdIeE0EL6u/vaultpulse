package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newRaftTestServer(t *testing.T, peers []RaftPeer) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/storage/raft/configuration" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"index": 42, "servers": peers},
		})
	}))
}

func TestNewRaftChecker_NotNil(t *testing.T) {
	c, _ := NewClient("http://127.0.0.1:8200", "tok")
	rc, err := NewRaftChecker(c)
	if err != nil || rc == nil {
		t.Fatal("expected non-nil RaftChecker")
	}
}

func TestNewRaftChecker_NilClient(t *testing.T) {
	_, err := NewRaftChecker(nil)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestRaftStatus_Success(t *testing.T) {
	peers := []RaftPeer{
		{NodeID: "n1", Leader: true, Voter: true},
		{NodeID: "n2", Leader: false, Voter: true},
		{NodeID: "n3", Leader: false, Voter: true},
	}
	srv := newRaftTestServer(t, peers)
	defer srv.Close()

	c, _ := NewClient(srv.URL, "tok")
	rc, _ := NewRaftChecker(c)
	status, err := rc.Status(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(status.Peers) != 3 {
		t.Fatalf("expected 3 peers, got %d", len(status.Peers))
	}
}

func TestRaftStatus_NonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c, _ := NewClient(srv.URL, "tok")
	rc, _ := NewRaftChecker(c)
	_, err := rc.Status(context.Background())
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
}
