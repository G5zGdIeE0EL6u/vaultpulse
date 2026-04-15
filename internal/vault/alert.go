package vault

import (
	"fmt"
	"time"
)

// Severity represents the urgency of an expiry alert.
type Severity string

const (
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Alert represents a secret expiry notification.
type Alert struct {
	Path      string
	ExpiresAt time.Time
	TTL       time.Duration
	LeaseID   string
	Severity  Severity
}

// String returns a human-readable summary of the alert.
func (a Alert) String() string {
	return fmt.Sprintf(
		"[%s] secret %q expires at %s (TTL: %s, lease: %q)",
		a.Severity,
		a.Path,
		a.ExpiresAt.Format(time.RFC3339),
		a.TTL.Round(time.Second),
		a.LeaseID,
	)
}

// IsExpired returns true if the secret has already expired.
func (a Alert) IsExpired() bool {
	return time.Now().After(a.ExpiresAt)
}

// TimeUntilExpiry returns the duration until the secret expires.
// Returns a negative duration if already expired.
func (a Alert) TimeUntilExpiry() time.Duration {
	return time.Until(a.ExpiresAt)
}
