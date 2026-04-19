package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newAWSTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/aws/roles":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"keys": []string{"my-role", "dev-role"}},
			})
		case "/v1/aws/roles/my-role":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"credential_type": "iam_user"},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestNewAWSScanner_NotNil(t *testing.T) {
	c := &Client{}
	s := NewAWSScanner(c, "")
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
	if s.mount != "aws" {
		t.Fatalf("expected default mount 'aws', got %s", s.mount)
	}
}

func TestNewAWSScanner_NilClient(t *testing.T) {
	if NewAWSScanner(nil, "") != nil {
		t.Fatal("expected nil for nil client")
	}
}

func TestAWSListRoles_Success(t *testing.T) {
	srv := newAWSTestServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	s := NewAWSScanner(c, "aws")
	roles, err := s.ListRoles()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roles) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(roles))
	}
}

func TestAWSGetRole_Success(t *testing.T) {
	srv := newAWSTestServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "test-token")
	s := NewAWSScanner(c, "aws")
	data, err := s.GetRole("my-role")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data["credential_type"] != "iam_user" {
		t.Fatalf("unexpected credential_type: %v", data["credential_type"])
	}
}

func TestAWSGetRole_EmptyName(t *testing.T) {
	c := &Client{}
	s := NewAWSScanner(c, "aws")
	_, err := s.GetRole("")
	if err == nil {
		t.Fatal("expected error for empty role name")
	}
}

func TestAWSCredential_IsExpired(t *testing.T) {
	cred := &AWSCredential{LeaseExpiry: time.Now().Add(-time.Minute)}
	if !cred.IsExpired() {
		t.Fatal("expected credential to be expired")
	}
}
