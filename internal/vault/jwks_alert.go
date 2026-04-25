package vault

import (
	"fmt"
	"time"
)

// JWKSAlerter evaluates JWKS keys and raises alerts for expiring or expired keys.
type JWKSAlerter struct {
	scanner         *JWKSScanner
	warningThreshold time.Duration
	criticalThreshold time.Duration
}

// NewJWKSAlerter creates a new JWKSAlerter. Returns nil if scanner is nil.
func NewJWKSAlerter(scanner *JWKSScanner) *JWKSAlerter {
	if scanner == nil {
		return nil
	}
	return &JWKSAlerter{
		scanner:           scanner,
		warningThreshold:  72 * time.Hour,
		criticalThreshold: 24 * time.Hour,
	}
}

// Evaluate scans JWKS keys for the given mount and returns alerts for
// keys that are expiring soon or already expired.
func (a *JWKSAlerter) Evaluate(mount string) ([]*Alert, error) {
	keys, err := a.scanner.ListKeys(mount)
	if err != nil {
		return nil, fmt.Errorf("jwks alerter evaluate: %w", err)
	}

	var alerts []*Alert
	for _, key := range keys {
		if key.ExpiresAt.IsZero() {
			continue
		}
		ttl := key.TimeUntilExpiry()
		var sev Severity
		switch {
		case key.IsExpired():
			sev = SeverityCritical
		case ttl <= a.criticalThreshold:
			sev = SeverityCritical
		case ttl <= a.warningThreshold:
			sev = SeverityWarning
		default:
			continue
		}
		alerts = append(alerts, &Alert{
			Path:      fmt.Sprintf("auth/%s/jwks/%s", mount, key.KeyID),
			Message:   fmt.Sprintf("JWKS key %q (alg=%s) expires in %s", key.KeyID, key.Algorithm, ttl.Round(time.Second)),
			Severity:  sev,
			ExpiresAt: key.ExpiresAt,
		})
	}
	return alerts, nil
}
