package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newSSHCATestServer(t *testing.T, status int, publicKey string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]string{"public_key": publicKey},
		})
	}))
}

func TestNewSSHCAScanner_NotNil(t *testing.T) {
	c := &Client{}
	s := NewSSHCAScanner(c, "")
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
	if s.mount != "ssh" {
		t.Errorf("expected default mount 'ssh', got %q", s.mount)
	}
}

func TestNewSSHCAScanner_NilClient(t *testing.T) {
	s := NewSSHCAScanner(nil, "ssh")
	if s != nil {
		t.Fatal("expected nil scanner for nil client")
	}
}

func TestSSHCAGetCAInfo_Success(t *testing.T) {
	srv := newSSHCATestServer(t, http.StatusOK, "ecdsa-sha2-nistp256 AAAA...")
	defer srv.Close()

	c := &Client{address: srv.URL, token: "test", http: srv.Client()}
	s := NewSSHCAScanner(c, "ssh")

	info, err := s.GetCAInfo()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.PublicKey == "" {
		t.Error("expected non-empty public key")
	}
	if info.Mount != "ssh" {
		t.Errorf("expected mount 'ssh', got %q", info.Mount)
	}
}

func TestSSHCAGetCAInfo_NotFound(t *testing.T) {
	srv := newSSHCATestServer(t, http.StatusNotFound, "")
	defer srv.Close()

	c := &Client{address: srv.URL, token: "test", http: srv.Client()}
	s := NewSSHCAScanner(c, "ssh")

	_, err := s.GetCAInfo()
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
}

func TestSSHCAAlerter_Evaluate_NoAlert(t *testing.T) {
	srv := newSSHCATestServer(t, http.StatusOK, "ecdsa-sha2-nistp256 AAAA...")
	defer srv.Close()

	c := &Client{address: srv.URL, token: "test", http: srv.Client()}
	s := NewSSHCAScanner(c, "ssh")
	alerter := NewSSHCAAlerter(s, nil)

	// No ExpiresAt set — should produce no alert.
	alert, err := alerter.Evaluate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alert != nil {
		t.Errorf("expected nil alert, got %+v", alert)
	}
}

func TestNewSSHCAAlerter_NilScanner(t *testing.T) {
	a := NewSSHCAAlerter(nil, nil)
	if a != nil {
		t.Fatal("expected nil alerter for nil scanner")
	}
}

func TestDefaultSSHCAAlertThresholds_NotEmpty(t *testing.T) {
	th := DefaultSSHCAAlertThresholds()
	if th.Warning <= 0 || th.Critical <= 0 {
		t.Error("expected positive default thresholds")
	}
	if th.Warning <= th.Critical {
		t.Error("expected warning threshold to be greater than critical")
	}
}

func TestSSHCAInfo_IsExpired(t *testing.T) {
	past := SSHCAInfo{ExpiresAt: time.Now().Add(-time.Hour)}
	if !past.IsExpired() {
		t.Error("expected expired")
	}
	future := SSHCAInfo{ExpiresAt: time.Now().Add(time.Hour)}
	if future.IsExpired() {
		t.Error("expected not expired")
	}
}
