package vault

import (
	"testing"
	"time"
)

func TestLoginTokenRecord_TTL_Positive(t *testing.T) {
	r := &LoginTokenRecord{
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	if r.TTL() <= 0 {
		t.Errorf("expected positive TTL, got %v", r.TTL())
	}
}

func TestLoginTokenRecord_TTL_Expired(t *testing.T) {
	r := &LoginTokenRecord{
		ExpiresAt: time.Now().Add(-5 * time.Minute),
	}
	if r.TTL() >= 0 {
		t.Errorf("expected negative TTL for expired token, got %v", r.TTL())
	}
}

func TestLoginTokenRecord_IsExpired_False(t *testing.T) {
	r := &LoginTokenRecord{
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	if r.IsExpired() {
		t.Error("expected token to not be expired")
	}
}

func TestLoginTokenRecord_IsExpired_True(t *testing.T) {
	r := &LoginTokenRecord{
		ExpiresAt: time.Now().Add(-1 * time.Second),
	}
	if !r.IsExpired() {
		t.Error("expected token to be expired")
	}
}

func TestNewLoginTokenScanner_NotNil(t *testing.T) {
	c := &Client{}
	s, err := NewLoginTokenScanner(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil {
		t.Error("expected non-nil scanner")
	}
}

func TestNewLoginTokenScanner_NilClient(t *testing.T) {
	_, err := NewLoginTokenScanner(nil)
	if err == nil {
		t.Error("expected error for nil client")
	}
}
