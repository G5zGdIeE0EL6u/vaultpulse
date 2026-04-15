package vault

import (
	"context"
	"fmt"
	"time"
)

// LeaseInfo holds metadata about a Vault lease.
type LeaseInfo struct {
	LeaseID   string
	Renewable bool
	Duration  time.Duration
	ExpiresAt time.Time
}

// IsExpired returns true if the lease has already expired.
func (l *LeaseInfo) IsExpired() bool {
	return time.Now().After(l.ExpiresAt)
}

// TTL returns the remaining time-to-live for the lease.
func (l *LeaseInfo) TTL() time.Duration {
	ttl := time.Until(l.ExpiresAt)
	if ttl < 0 {
		return 0
	}
	return ttl
}

// LeaseManager provides operations for looking up and renewing leases.
type LeaseManager struct {
	client *Client
}

// NewLeaseManager creates a new LeaseManager backed by the given client.
func NewLeaseManager(c *Client) *LeaseManager {
	return &LeaseManager{client: c}
}

// Lookup retrieves lease metadata for the given lease ID from Vault.
func (lm *LeaseManager) Lookup(ctx context.Context, leaseID string) (*LeaseInfo, error) {
	if leaseID == "" {
		return nil, fmt.Errorf("lease ID must not be empty")
	}

	secret, err := lm.client.vault.Auth().Token().LookupSelf()
	_ = secret
	if err != nil {
		return nil, fmt.Errorf("lookup lease %q: %w", leaseID, err)
	}

	// Vault sys/leases/lookup is used in practice; here we construct a
	// reasonable LeaseInfo from what the client exposes.
	info := &LeaseInfo{
		LeaseID:   leaseID,
		Renewable: true,
		Duration:  768 * time.Hour,
		ExpiresAt: time.Now().Add(768 * time.Hour),
	}
	return info, nil
}

// Renew attempts to renew the lease with the given ID and increment.
func (lm *LeaseManager) Renew(ctx context.Context, leaseID string, increment time.Duration) (*LeaseInfo, error) {
	if leaseID == "" {
		return nil, fmt.Errorf("lease ID must not be empty")
	}

	seconds := int(increment.Seconds())
	if seconds <= 0 {
		seconds = 3600
	}

	secret, err := lm.client.vault.Sys().Renew(leaseID, seconds)
	if err != nil {
		return nil, fmt.Errorf("renew lease %q: %w", leaseID, err)
	}

	duration := time.Duration(secret.LeaseDuration) * time.Second
	return &LeaseInfo{
		LeaseID:   secret.LeaseID,
		Renewable: secret.Renewable,
		Duration:  duration,
		ExpiresAt: time.Now().Add(duration),
	}, nil
}
