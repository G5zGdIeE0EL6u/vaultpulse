package vault

import (
	"testing"
	"time"
)

func TestWrappedSecret_IsExpired_False(t *testing.T) {
	w := &WrappedSecret{
		CreatedAt: time.Now(),
		TTL:       10 * time.Minute,
	}
	if w.IsExpired() {
		t.Fatal("expected not expired")
	}
}

func TestWrappedSecret_IsExpired_True(t *testing.T) {
	w := &WrappedSecret{
		CreatedAt: time.Now().Add(-20 * time.Minute),
		TTL:       5 * time.Minute,
	}
	if !w.IsExpired() {
		t.Fatal("expected expired")
	}
}

func TestWrappedSecret_TimeUntilExpiry_Positive(t *testing.T) {
	w := &WrappedSecret{
		CreatedAt: time.Now(),
		TTL:       10 * time.Minute,
	}
	if w.TimeUntilExpiry() <= 0 {
		t.Fatal("expected positive time until expiry")
	}
}

func TestNewWrappingManager_NotNil(t *testing.T) {
	c := &Client{}
	wm, err := NewWrappingManager(c)
	if err != nil || wm == nil {
		t.Fatalf("expected non-nil manager, got err=%v", err)
	}
}

func TestNewWrappingManager_NilClient(t *testing.T) {
	_, err := NewWrappingManager(nil)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestNewWrappingAlerter_NotNil(t *testing.T) {
	wm, _ := NewWrappingManager(&Client{})
	wa, err := NewWrappingAlerter(wm, nil)
	if err != nil || wa == nil {
		t.Fatalf("expected non-nil alerter, got err=%v", err)
	}
}

func TestNewWrappingAlerter_DefaultThresholds(t *testing.T) {
	wm, _ := NewWrappingManager(&Client{})
	wa, _ := NewWrappingAlerter(wm, nil)
	if len(wa.thresholds) == 0 {
		t.Fatal("expected default thresholds to be set")
	}
}

func TestWrappingAlerter_Evaluate_Expired(t *testing.T) {
	wm, _ := NewWrappingManager(&Client{})
	wa, _ := NewWrappingAlerter(wm, nil)
	w := &WrappedSecret{
		CreatedAt: time.Now().Add(-10 * time.Minute),
		TTL:       1 * time.Minute,
		Accessor:  "abc123",
	}
	alert, err := wa.Evaluate(w)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alert == nil || alert.Severity != SeverityCritical {
		t.Fatal("expected critical alert for expired token")
	}
}

func TestWrappingAlerter_Evaluate_NoAlert(t *testing.T) {
	wm, _ := NewWrappingManager(&Client{})
	wa, _ := NewWrappingAlerter(wm, nil)
	w := &WrappedSecret{
		CreatedAt: time.Now(),
		TTL:       1 * time.Hour,
		Accessor:  "abc123",
	}
	alert, err := wa.Evaluate(w)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alert != nil {
		t.Fatal("expected no alert for healthy token")
	}
}
