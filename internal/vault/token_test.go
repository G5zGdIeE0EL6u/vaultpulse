package vault

import (
	"testing"
	"time"
)

func TestTokenInfo_IsExpired_False(t *testing.T) {
	info := &TokenInfo{
		ExpireTime: time.Now().Add(10 * time.Minute),
	}
	if info.IsExpired() {
		t.Error("expected token to not be expired")
	}
}

func TestTokenInfo_IsExpired_True(t *testing.T) {
	info := &TokenInfo{
		ExpireTime: time.Now().Add(-1 * time.Minute),
	}
	if !info.IsExpired() {
		t.Error("expected token to be expired")
	}
}

func TestTokenInfo_TimeUntilExpiry_Positive(t *testing.T) {
	info := &TokenInfo{
		ExpireTime: time.Now().Add(5 * time.Minute),
	}
	if info.TimeUntilExpiry() <= 0 {
		t.Error("expected positive duration until expiry")
	}
}

func TestTokenInfo_TimeUntilExpiry_Negative(t *testing.T) {
	info := &TokenInfo{
		ExpireTime: time.Now().Add(-5 * time.Minute),
	}
	if info.TimeUntilExpiry() >= 0 {
		t.Error("expected negative duration for expired token")
	}
}

func TestNewTokenInspector_NotNil(t *testing.T) {
	c := &Client{}
	inspector := NewTokenInspector(c)
	if inspector == nil {
		t.Fatal("expected non-nil TokenInspector")
	}
	if inspector.client != c {
		t.Error("expected inspector to hold provided client")
	}
}

func TestTokenInfo_Policies(t *testing.T) {
	info := &TokenInfo{
		Policies:   []string{"default", "admin"},
		ExpireTime: time.Now().Add(1 * time.Hour),
	}
	if len(info.Policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(info.Policies))
	}
}
