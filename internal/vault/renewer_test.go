package vault

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewRenewer_DefaultThreshold(t *testing.T) {
	client := &Client{}
	r := NewRenewer(client, 0)
	if r.threshold != 24*time.Hour {
		t.Errorf("expected default threshold 24h, got %s", r.threshold)
	}
}

func TestNewRenewer_CustomThreshold(t *testing.T) {
	client := &Client{}
	r := NewRenewer(client, 6*time.Hour)
	if r.threshold != 6*time.Hour {
		t.Errorf("expected threshold 6h, got %s", r.threshold)
	}
}

func TestRenewIfNeeded_AboveThreshold(t *testing.T) {
	client := &Client{}
	r := NewRenewer(client, 1*time.Hour)

	alert := Alert{
		Path:      "secret/data/myapp",
		ExpiresAt: time.Now().Add(48 * time.Hour),
	}

	result := r.RenewIfNeeded(context.Background(), alert)
	if result.Renewed {
		t.Error("expected no renewal when TTL is above threshold")
	}
	if result.Error != nil {
		t.Errorf("unexpected error: %v", result.Error)
	}
}

func TestRenewIfNeeded_Expired(t *testing.T) {
	client := &Client{}
	r := NewRenewer(client, 1*time.Hour)

	alert := Alert{
		Path:      "secret/data/myapp",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	}

	result := r.RenewIfNeeded(context.Background(), alert)
	if result.Error == nil {
		t.Error("expected error for expired secret")
	}
	if result.Renewed {
		t.Error("should not mark as renewed when already expired")
	}
}

func TestRenewIfNeeded_BelowThreshold_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"value":"s3cr3t"},"lease_duration":7200}`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "test-token")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	r := NewRenewer(client, 2*time.Hour)
	alert := Alert{
		Path:      "secret/data/myapp",
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}

	result := r.RenewIfNeeded(context.Background(), alert)
	if result.Error != nil {
		t.Errorf("unexpected error: %v", result.Error)
	}
	if !result.Renewed {
		t.Error("expected renewal when TTL is below threshold")
	}
	if result.NewTTL != 7200*time.Second {
		t.Errorf("expected new TTL 7200s, got %s", result.NewTTL)
	}
}
