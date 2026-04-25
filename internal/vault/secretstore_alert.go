package vault

import (
	"fmt"
	"time"
)

// SecretStoreThresholds defines warning/critical TTL boundaries.
type SecretStoreThresholds struct {
	Warning  time.Duration
	Critical time.Duration
}

// DefaultSecretStoreThresholds returns sensible defaults.
func DefaultSecretStoreThresholds() SecretStoreThresholds {
	return SecretStoreThresholds{
		Warning:  72 * time.Hour,
		Critical: 24 * time.Hour,
	}
}

// SecretStoreAlerter evaluates SecretStoreEntry objects and emits alerts.
type SecretStoreAlerter struct {
	scanner    *SecretStoreScanner
	thresholds SecretStoreThresholds
}

// NewSecretStoreAlerter creates a new SecretStoreAlerter.
func NewSecretStoreAlerter(scanner *SecretStoreScanner, thresholds SecretStoreThresholds) *SecretStoreAlerter {
	if scanner == nil {
		return nil
	}
	return &SecretStoreAlerter{scanner: scanner, thresholds: thresholds}
}

// Evaluate checks the given entries and returns alerts for expiring secrets.
func (a *SecretStoreAlerter) Evaluate(entries []*SecretStoreEntry) []*Alert {
	var alerts []*Alert
	for _, entry := range entries {
		if entry == nil || entry.ExpiresAt.IsZero() {
			continue
		}
		ttl := entry.TTL()
		var sev Severity
		switch {
		case ttl <= 0:
			sev = SeverityCritical
		case ttl <= a.thresholds.Critical:
			sev = SeverityCritical
		case ttl <= a.thresholds.Warning:
			sev = SeverityWarning
		default:
			continue
		}
		alerts = append(alerts, &Alert{
			Path:      entry.Path,
			Message:   fmt.Sprintf("secret %q expires in %s", entry.Path, ttl.Round(time.Second)),
			Severity:  sev,
			ExpiresAt: entry.ExpiresAt,
		})
	}
	return alerts
}
