package vault

import (
	"fmt"
	"time"
)

// SSHCAAlertThresholds defines warning and critical TTL thresholds for SSH CA keys.
type SSHCAAlertThresholds struct {
	Warning  time.Duration
	Critical time.Duration
}

// DefaultSSHCAAlertThresholds returns sensible defaults for SSH CA alerting.
func DefaultSSHCAAlertThresholds() SSHCAAlertThresholds {
	return SSHCAAlertThresholds{
		Warning:  30 * 24 * time.Hour,
		Critical: 7 * 24 * time.Hour,
	}
}

// SSHCAAlerter evaluates SSH CA key expiry and emits alerts.
type SSHCAAlerter struct {
	scanner    *SSHCAScanner
	thresholds SSHCAAlertThresholds
}

// NewSSHCAAlerter creates a new SSHCAAlerter with the given scanner and thresholds.
// If thresholds is nil, defaults are used.
func NewSSHCAAlerter(scanner *SSHCAScanner, thresholds *SSHCAAlertThresholds) *SSHCAAlerter {
	if scanner == nil {
		return nil
	}
	t := DefaultSSHCAAlertThresholds()
	if thresholds != nil {
		t = *thresholds
	}
	return &SSHCAAlerter{scanner: scanner, thresholds: t}
}

// Evaluate fetches the SSH CA info and returns an Alert if the key is
// expiring soon or has already expired. Returns nil if healthy.
func (a *SSHCAAlerter) Evaluate() (*Alert, error) {
	info, err := a.scanner.GetCAInfo()
	if err != nil {
		return nil, fmt.Errorf("sshca alerter: %w", err)
	}

	if info.ExpiresAt.IsZero() {
		// No expiry configured — nothing to alert on.
		return nil, nil
	}

	ttl := info.TimeUntilExpiry()
	var severity Severity
	switch {
	case ttl <= 0:
		severity = SeverityCritical
	case ttl <= a.thresholds.Critical:
		severity = SeverityCritical
	case ttl <= a.thresholds.Warning:
		severity = SeverityWarning
	default:
		return nil, nil
	}

	return &Alert{
		Path:      fmt.Sprintf("%s/config/ca", info.Mount),
		Message:   fmt.Sprintf("SSH CA on mount %q expires in %s", info.Mount, ttl.Round(time.Second)),
		Severity:  severity,
		ExpiresAt: info.ExpiresAt,
	}, nil
}
