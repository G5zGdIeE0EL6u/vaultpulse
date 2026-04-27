package vault

import (
	"fmt"
	"time"
)

// DefaultTokenTTLThresholds defines default warning/critical TTL thresholds.
func DefaultTokenTTLThresholds() map[string]time.Duration {
	return map[string]time.Duration{
		"warning":  24 * time.Hour,
		"critical": 6 * time.Hour,
	}
}

// TokenTTLAlerter evaluates token TTL entries and produces alerts.
type TokenTTLAlerter struct {
	scanner    *TokenTTLScanner
	thresholds map[string]time.Duration
}

// NewTokenTTLAlerter creates a new TokenTTLAlerter.
// Returns nil if scanner is nil.
func NewTokenTTLAlerter(scanner *TokenTTLScanner, thresholds map[string]time.Duration) *TokenTTLAlerter {
	if scanner == nil {
		return nil
	}
	if thresholds == nil {
		thresholds = DefaultTokenTTLThresholds()
	}
	return &TokenTTLAlerter{scanner: scanner, thresholds: thresholds}
}

// Evaluate inspects a TokenTTLEntry and returns an Alert if thresholds are breached.
// Returns nil if the token is healthy.
func (a *TokenTTLAlerter) Evaluate(entry *TokenTTLEntry) *Alert {
	if entry == nil {
		return nil
	}
	ttl := entry.TimeUntilExpiry()
	critical := a.thresholds["critical"]
	warning := a.thresholds["warning"]

	var severity Severity
	switch {
	case ttl <= critical:
		severity = SeverityCritical
	case ttl <= warning:
		severity = SeverityWarning
	default:
		return nil
	}

	return &Alert{
		Path:      fmt.Sprintf("token/accessor/%s", entry.Accessor),
		Message:   fmt.Sprintf("token '%s' expires in %s", entry.DisplayName, ttl.Round(time.Second)),
		Severity:  severity,
		ExpiresAt: time.Now().Add(ttl),
	}
}
