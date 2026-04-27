package vault

import (
	"fmt"
	"time"
)

// FireSecretAlerter evaluates FireSecretEntry items and emits Alerts.
type FireSecretAlerter struct {
	scanner            *FireSecretScanner
	warningThreshold   time.Duration
	criticalThreshold  time.Duration
}

// NewFireSecretAlerter creates a FireSecretAlerter with the given thresholds.
// Returns an error if scanner is nil.
func NewFireSecretAlerter(scanner *FireSecretScanner, warning, critical time.Duration) (*FireSecretAlerter, error) {
	if scanner == nil {
		return nil, fmt.Errorf("fire secret scanner must not be nil")
	}
	if warning == 0 {
		warning = 72 * time.Hour
	}
	if critical == 0 {
		critical = 24 * time.Hour
	}
	return &FireSecretAlerter{
		scanner:           scanner,
		warningThreshold:  warning,
		criticalThreshold: critical,
	}, nil
}

// Evaluate checks a FireSecretEntry and returns an Alert if thresholds are breached.
// Returns nil if the entry is not near expiry.
func (a *FireSecretAlerter) Evaluate(entry *FireSecretEntry) *Alert {
	if entry == nil || entry.ExpiresAt.IsZero() {
		return nil
	}
	ttl := entry.TimeUntilExpiry()
	var severity Severity
	switch {
	case ttl <= 0:
		severity = SeverityCritical
	case ttl <= a.criticalThreshold:
		severity = SeverityCritical
	case ttl <= a.warningThreshold:
		severity = SeverityWarning
	default:
		return nil
	}
	return &Alert{
		Path:      entry.Path,
		Message:   fmt.Sprintf("fire secret %q expires in %s", entry.Key, ttl.Round(time.Second)),
		Severity:  severity,
		ExpiresAt: entry.ExpiresAt,
	}
}
