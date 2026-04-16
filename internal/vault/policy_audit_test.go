package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newPolicyAuditServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/sys/policy/mypolicy":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"paths": []interface{}{"secret/data/foo"},
				},
				"paths": []interface{}{"secret/data/foo"},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestNewPolicyAuditor_NotNil(t *testing.T) {
	srv := newPolicyAuditServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "token")
	checker := NewPolicyChecker(c)
	scanner := NewScanner(c)
	auditor := NewPolicyAuditor(checker, scanner)
	if auditor == nil {
		t.Fatal("expected non-nil PolicyAuditor")
	}
}

func TestPolicyAuditor_Audit_InvalidPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c, _ := NewClient(srv.URL, "token")
	checker := NewPolicyChecker(c)
	scanner := NewScanner(c)
	auditor := NewPolicyAuditor(checker, scanner)
	_, err := auditor.Audit(context.Background(), "ghost")
	if err == nil {
		t.Fatal("expected error for missing policy")
	}
}

func TestPolicyAuditor_Audit_EmptyPaths(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"paths": []interface{}{},
		})
	}))
	defer srv.Close()
	c, _ := NewClient(srv.URL, "token")
	checker := NewPolicyChecker(c)
	scanner := NewScanner(c)
	auditor := NewPolicyAuditor(checker, scanner)
	results, err := auditor.Audit(context.Background(), "empty")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}
