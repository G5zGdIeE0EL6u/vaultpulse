package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newQuotaTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/sys/quotas/rate-limit":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"keys": []string{"global", "kv-limit"}},
			})
		case "/v1/sys/quotas/rate-limit/global":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": QuotaInfo{Name: "global", Path: "", Type: "rate-limit", Rate: 100},
			})
		case "/v1/sys/quotas/rate-limit/kv-limit":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": QuotaInfo{Name: "kv-limit", Path: "secret/", Type: "rate-limit", Rate: 5},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestNewQuotaChecker_NotNil(t *testing.T) {
	srv := newQuotaTestServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "token")
	qc, err := NewQuotaChecker(c)
	if err != nil || qc == nil {
		t.Fatal("expected non-nil QuotaChecker")
	}
}

func TestNewQuotaChecker_NilClient(t *testing.T) {
	_, err := NewQuotaChecker(nil)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestListQuotas_Success(t *testing.T) {
	srv := newQuotaTestServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "token")
	qc, _ := NewQuotaChecker(c)
	keys, err := qc.ListQuotas()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
}

func TestGetQuota_EmptyName(t *testing.T) {
	srv := newQuotaTestServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "token")
	qc, _ := NewQuotaChecker(c)
	_, err := qc.GetQuota("")
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestGetQuota_Success(t *testing.T) {
	srv := newQuotaTestServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "token")
	qc, _ := NewQuotaChecker(c)
	info, err := qc.GetQuota("global")
	if err != nil || info == nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Rate != 100 {
		t.Errorf("expected rate 100, got %f", info.Rate)
	}
}
