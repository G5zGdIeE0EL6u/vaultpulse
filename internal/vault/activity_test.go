package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newActivityTestServer(t *testing.T, status int, payload interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func TestNewActivityChecker_NotNil(t *testing.T) {
	server := newActivityTestServer(t, http.StatusOK, nil)
	defer server.Close()

	client, err := NewClient(server.URL, "test-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	checker, err := NewActivityChecker(client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if checker == nil {
		t.Fatal("expected non-nil ActivityChecker")
	}
}

func TestNewActivityChecker_NilClient(t *testing.T) {
	_, err := NewActivityChecker(nil)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestActivityChecker_GetSummary_Success(t *testing.T) {
	start := time.Now().Add(-24 * time.Hour)
	end := time.Now()

	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"start_time":                    start.UTC().Format(time.RFC3339),
			"end_time":                      end.UTC().Format(time.RFC3339),
			"distinct_entities":             42,
			"distinct_non_entity_tokens":    7,
			"by_namespace":                  []interface{}{},
		},
	}

	server := newActivityTestServer(t, http.StatusOK, payload)
	defer server.Close()

	client, _ := NewClient(server.URL, "test-token")
	checker, _ := NewActivityChecker(client)

	summary, err := checker.GetSummary(start, end)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if summary == nil {
		t.Fatal("expected non-nil summary")
	}
	if summary.DistinctEntities != 42 {
		t.Errorf("expected 42 distinct entities, got %d", summary.DistinctEntities)
	}
	if summary.DistinctNonEntities != 7 {
		t.Errorf("expected 7 non-entity tokens, got %d", summary.DistinctNonEntities)
	}
}

func TestActivityChecker_GetSummary_NonOK(t *testing.T) {
	server := newActivityTestServer(t, http.StatusForbidden, nil)
	defer server.Close()

	client, _ := NewClient(server.URL, "test-token")
	checker, _ := NewActivityChecker(client)

	_, err := checker.GetSummary(time.Now().Add(-time.Hour), time.Now())
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
}
