package vault

import (
	"context"
	"testing"
	"time"
)

func TestLeaseInfo_TTL_Positive(t *testing.T) {
	l := &LeaseInfo{
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	ttl := l.TTL()
	if ttl <= 0 {
		t.Errorf("expected positive TTL, got %v", ttl)
	}
	if ttl > 5*time.Minute {
		t.Errorf("TTL %v exceeds expected max", ttl)
	}
}

func TestLeaseInfo_TTL_Expired(t *testing.T) {
	l := &LeaseInfo{
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	}
	if l.TTL() != 0 {
		t.Errorf("expected TTL of 0 for expired lease, got %v", l.TTL())
	}
}

func TestLeaseInfo_IsExpired_False(t *testing.T) {
	l := &LeaseInfo{
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	if l.IsExpired() {
		t.Error("expected lease to not be expired")
	}
}

func TestLeaseInfo_IsExpired_True(t *testing.T) {
	l := &LeaseInfo{
		ExpiresAt: time.Now().Add(-1 * time.Second),
	}
	if !l.IsExpired() {
		t.Error("expected lease to be expired")
	}
}

func TestNewLeaseManager_NotNil(t *testing.T) {
	server := newMockVaultServer(t)
	client, err := NewClient(server.URL, "test-token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	lm := NewLeaseManager(client)
	if lm == nil {
		t.Fatal("expected non-nil LeaseManager")
	}
}

func TestLeaseManager_Lookup_EmptyID(t *testing.T) {
	server := newMockVaultServer(t)
	client, err := NewClient(server.URL, "test-token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	lm := NewLeaseManager(client)
	_, err = lm.Lookup(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty lease ID")
	}
}

func TestLeaseManager_Renew_EmptyID(t *testing.T) {
	server := newMockVaultServer(t)
	client, err := NewClient(server.URL, "test-token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	lm := NewLeaseManager(client)
	_, err = lm.Renew(context.Background(), "", time.Hour)
	if err == nil {
		t.Error("expected error for empty lease ID")
	}
}
