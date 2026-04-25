package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newGCPKMSTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/gcpkms/keys":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"keys": []string{"my-key"}},
			})
		case "/v1/gcpkms/keys/my-key":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"key_ring":        "projects/p/locations/global/keyRings/kr",
					"crypto_key":      "projects/p/locations/global/keyRings/kr/cryptoKeys/my-key",
					"rotation_period": 86400,
					"last_rotated":    time.Now().Add(-48 * time.Hour),
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestNewGCPKMSScanner_NotNil(t *testing.T) {
	srv := newGCPKMSTestServer(t)
	defer srv.Close()
	client, _ := NewClient(srv.URL, "test-token")
	s, err := NewGCPKMSScanner(client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
	if s.mount != "gcpkms" {
		t.Errorf("expected default mount 'gcpkms', got %q", s.mount)
	}
}

func TestNewGCPKMSScanner_NilClient(t *testing.T) {
	_, err := NewGCPKMSScanner(nil, "gcpkms")
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestGCPKMSListKeys_Success(t *testing.T) {
	srv := newGCPKMSTestServer(t)
	defer srv.Close()
	client, _ := NewClient(srv.URL, "test-token")
	s, _ := NewGCPKMSScanner(client, "gcpkms")
	keys, err := s.ListKeys()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 || keys[0] != "my-key" {
		t.Errorf("unexpected keys: %v", keys)
	}
}

func TestGCPKMSGetKey_EmptyName(t *testing.T) {
	srv := newGCPKMSTestServer(t)
	defer srv.Close()
	client, _ := NewClient(srv.URL, "test-token")
	s, _ := NewGCPKMSScanner(client, "gcpkms")
	_, err := s.GetKey("")
	if err == nil {
		t.Fatal("expected error for empty key name")
	}
}

func TestGCPKMSKey_DueForRotation(t *testing.T) {
	key := &GCPKMSKey{
		Name:           "old-key",
		RotationPeriod: 86400,
		LastRotated:    time.Now().Add(-48 * time.Hour),
	}
	if !key.DueForRotation() {
		t.Error("expected key to be due for rotation")
	}
}

func TestGCPKMSKey_NotDueForRotation(t *testing.T) {
	key := &GCPKMSKey{
		Name:           "fresh-key",
		RotationPeriod: 86400,
		LastRotated:    time.Now().Add(-1 * time.Hour),
	}
	if key.DueForRotation() {
		t.Error("expected key to NOT be due for rotation")
	}
}
