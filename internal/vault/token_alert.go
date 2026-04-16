package vault

import (
	"context"
	"fmt"
	"time"
)

// TokenAlertThresholds defines TTL thresholds for token alerts.
type TokenAlertThresholds struct {
	Critical time.Duration
	Warning  time.Duration
}

// DefaultTokenAlertThresholds returns sensible defaults.
func DefaultTokenAlertThresholds() TokenAlertThresholds {
	return TokenAlertThresholds{
		Critical: 1 * time.Hour,
		Warning:  24 * time.Hour,
	}
}

// TokenAlerter checks token TTL and produces alerts.
type TokenAlerter struct {
	inspector  *TokenInspector
	thresholds TokenAlertThresholds
}

// NewTokenAlerter creates a TokenAlerter with given thresholds.
func NewTokenAlerter(inspector *TokenInspector, thresholds TokenAlertThresholds) *TokenAlerter {
	return &TokenAlerter{
		inspector:  inspector,
		thresholds: thresholds,
	}
}

// Check inspects the current token and returns an Alert if TTL is below a threshold.
func (ta *TokenAlerter) Check(ctx context.Context) (*Alert, error) {
	info, err := ta.inspector.LookupSelf(ctx)
	if err != nil {
		return nil, fmt.Errorf("token alerter check: %w", err)
	}

	ttl := info.TimeUntilExpiry()
	var severity Severity
	switch {
	case ttl <= ta.thresholds.Critical:
		severity = SeverityCritical
	case ttl <= ta.thresholds.Warning:
		severity = SeverityWarning
	default:
		return nil, nil
	}

	return &Alert{
		Path:      "auth/token/self",
		ExpiresAt: info.ExpireTime,
		Severity:  severity,
		Message:   fmt.Sprintf("token (accessor: %s) expires in %s", info.Accessor, ttl.Round(time.Second)),
	}, nil
}
