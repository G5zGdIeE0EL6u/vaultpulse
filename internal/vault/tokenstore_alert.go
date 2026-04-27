package vault

import (
	"fmt"
	"time"
)

// TokenStoreThresholds defines TTL thresholds for token store alerting.
type TokenStoreThresholds struct {
	Warning  time.Duration
	Critical time.Duration
}

// DefaultTokenStoreThresholds returns sensible default alert thresholds.
func DefaultTokenStoreThresholds() TokenStoreThresholds {
	return TokenStoreThresholds{
		Warning:  48 * time.Hour,
		Critical: 12 * time.Hour,
	}
}

// TokenStoreAlerter evaluates token store entries and produces alerts.
type TokenStoreAlerter struct {
	scanner    *TokenStoreScanner
	thresholds TokenStoreThresholds
}

// NewTokenStoreAlerter creates a new TokenStoreAlerter.
func NewTokenStoreAlerter(scanner *TokenStoreScanner, thresholds TokenStoreThresholds) (*TokenStoreAlerter, error) {
	if scanner == nil {
		return nil, fmt.Errorf("tokenstore alerter: scanner must not be nil")
	}
	return &TokenStoreAlerter{scanner: scanner, thresholds: thresholds}, nil
}

// Evaluate lists all accessors and returns alerts for entries nearing expiry.
func (a *TokenStoreAlerter) Evaluate() ([]*Alert, error) {
	accessors, err := a.scanner.ListAccessors()
	if err != nil {
		return nil, fmt.Errorf("tokenstore alerter: list accessors: %w", err)
	}
	var alerts []*Alert
	for _, acc := range accessors {
		entry, err := a.scanner.LookupAccessor(acc)
		if err != nil || entry.TTL <= 0 {
			continue
		}
		ttl := entry.TimeUntilExpiry()
		var sev Severity
		switch {
		case ttl <= a.thresholds.Critical:
			sev = SeverityCritical
		case ttl <= a.thresholds.Warning:
			sev = SeverityWarning
		default:
			continue
		}
		alerts = append(alerts, &Alert{
			Path:      fmt.Sprintf("auth/token/accessor/%s", acc),
			Severity:  sev,
			Message:   fmt.Sprintf("token accessor %s expires in %s (display: %s)", acc, ttl.Round(time.Minute), entry.DisplayName),
			ExpiresAt: entry.ExpireTime,
		})
	}
	return alerts, nil
}
