package vault

import (
	"fmt"
	"time"
)

// TokenAlertThreshold defines a TTL boundary and its associated severity.
type TokenAlertThreshold struct {
	Below    time.Duration
	Severity Severity
}

// DefaultTokenAlertThresholds returns the standard alert thresholds for tokens.
func DefaultTokenAlertThresholds() []TokenAlertThreshold {
	return []TokenAlertThreshold{
		{Below: 1 * time.Hour, Severity: SeverityCritical},
		{Below: 12 * time.Hour, Severity: SeverityHigh},
		{Below: 24 * time.Hour, Severity: SeverityMedium},
		{Below: 72 * time.Hour, Severity: SeverityLow},
	}
}

// TokenAlerter evaluates a TokenInfo against configured thresholds.
type TokenAlerter struct {
	thresholds []TokenAlertThreshold
}

// NewTokenAlerter creates a TokenAlerter with the given thresholds.
func NewTokenAlerter(thresholds []TokenAlertThreshold) *TokenAlerter {
	return &TokenAlerter{thresholds: thresholds}
}

// Evaluate checks the token's remaining TTL and returns any triggered alerts.
func (ta *TokenAlerter) Evaluate(info *TokenInfo) []Alert {
	if info == nil {
		return nil
	}
	ttl := time.Until(info.ExpireTime)
	var alerts []Alert
	for _, threshold := range ta.thresholds {
		if ttl < threshold.Below {
			alerts = append(alerts, Alert{
				Path:      "token",
				Severity:  threshold.Severity,
				Message:   fmt.Sprintf("token expires in %s (renewable: %v)", ttl.Round(time.Second), info.Renewable),
				ExpiresAt: info.ExpireTime,
			})
			break
		}
	}
	return alerts
}
