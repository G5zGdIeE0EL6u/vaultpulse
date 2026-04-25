package vault

import (
	"fmt"
	"time"
)

// DefaultTokenRoleThresholds defines warning/critical TTL thresholds for token roles.
var DefaultTokenRoleThresholds = map[string]time.Duration{
	"warning":  72 * time.Hour,
	"critical": 24 * time.Hour,
}

// TokenRoleAlerter evaluates token roles and emits Alerts.
type TokenRoleAlerter struct {
	scanner    *TokenRoleScanner
	thresholds map[string]time.Duration
}

// NewTokenRoleAlerter creates a TokenRoleAlerter.
// Returns an error if scanner is nil.
func NewTokenRoleAlerter(s *TokenRoleScanner, thresholds map[string]time.Duration) (*TokenRoleAlerter, error) {
	if s == nil {
		return nil, fmt.Errorf("token role scanner must not be nil")
	}
	if thresholds == nil {
		thresholds = DefaultTokenRoleThresholds
	}
	return &TokenRoleAlerter{scanner: s, thresholds: thresholds}, nil
}

// Evaluate lists all token roles and returns Alerts for those nearing expiry.
func (a *TokenRoleAlerter) Evaluate() ([]*Alert, error) {
	names, err := a.scanner.ListRoles()
	if err != nil {
		return nil, fmt.Errorf("evaluating token roles: %w", err)
	}
	var alerts []*Alert
	for _, name := range names {
		role, err := a.scanner.GetRole(name)
		if err != nil || role == nil {
			continue
		}
		ttl := role.ExplicitMaxTTL
		if ttl <= 0 {
			continue
		}
		sev := ""
		if ttl <= a.thresholds["critical"] {
			sev = SeverityCritical
		} else if ttl <= a.thresholds["warning"] {
			sev = SeverityWarning
		}
		if sev == "" {
			continue
		}
		alerts = append(alerts, &Alert{
			Path:      fmt.Sprintf("auth/token/roles/%s", name),
			Severity:  sev,
			Message:   fmt.Sprintf("token role %q explicit max TTL expires in %s", name, ttl.Round(time.Second)),
			ExpiresAt: time.Now().Add(ttl),
		})
	}
	return alerts, nil
}
