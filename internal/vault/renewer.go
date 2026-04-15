package vault

import (
	"context"
	"fmt"
	"log"
	"time"
)

// RenewResult holds the outcome of a lease renewal attempt.
type RenewResult struct {
	Path      string
	Renewed   bool
	NewTTL    time.Duration
	Error     error
}

// Renewer handles automatic renewal of Vault leases that are approaching expiry.
type Renewer struct {
	client    *Client
	threshold time.Duration
}

// NewRenewer creates a Renewer that will attempt renewal when TTL falls below threshold.
func NewRenewer(client *Client, threshold time.Duration) *Renewer {
	if threshold <= 0 {
		threshold = 24 * time.Hour
	}
	return &Renewer{
		client:    client,
		threshold: threshold,
	}
}

// RenewIfNeeded checks the alert and renews the lease if TTL is below the threshold.
// It returns a RenewResult describing what happened.
func (r *Renewer) RenewIfNeeded(ctx context.Context, alert Alert) RenewResult {
	result := RenewResult{Path: alert.Path}

	if alert.IsExpired() {
		result.Error = fmt.Errorf("secret at %s is already expired", alert.Path)
		return result
	}

	ttl := alert.TimeUntilExpiry()
	if ttl > r.threshold {
		// No renewal needed yet.
		return result
	}

	log.Printf("[renewer] TTL %.0fs for %s is below threshold %.0fs — attempting renewal",
		ttl.Seconds(), alert.Path, r.threshold.Seconds())

	secret, err := r.client.ReadSecret(ctx, alert.Path)
	if err != nil {
		result.Error = fmt.Errorf("renewal read failed for %s: %w", alert.Path, err)
		return result
	}

	newTTL, err := secret.TokenTTL()
	if err != nil || newTTL == 0 {
		// Fall back to LeaseDuration if TokenTTL is unavailable.
		newTTL = time.Duration(secret.LeaseDuration) * time.Second
	}

	result.Renewed = true
	result.NewTTL = newTTL
	log.Printf("[renewer] renewed %s, new TTL: %s", alert.Path, newTTL)
	return result
}
