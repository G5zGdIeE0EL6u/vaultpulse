package vault

import (
	"fmt"
	"time"
)

// OktaAlerter evaluates Okta users and emits alerts for expiring entries.
type OktaAlerter struct {
	scanner    *OktaScanner
	warningTTL time.Duration
	criticalTTL time.Duration
}

// NewOktaAlerter creates a new OktaAlerter. Returns nil if scanner is nil.
func NewOktaAlerter(scanner *OktaScanner, warning, critical time.Duration) *OktaAlerter {
	if scanner == nil {
		return nil
	}
	if warning == 0 {
		warning = 72 * time.Hour
	}
	if critical == 0 {
		critical = 24 * time.Hour
	}
	return &OktaAlerter{scanner: scanner, warningTTL: warning, criticalTTL: critical}
}

// Evaluate lists all Okta users and returns alerts for those nearing expiry.
func (a *OktaAlerter) Evaluate() ([]*Alert, error) {
	users, err := a.scanner.ListUsers()
	if err != nil {
		return nil, fmt.Errorf("okta alerter evaluate: %w", err)
	}
	var alerts []*Alert
	for _, username := range users {
		user, err := a.scanner.GetUser(username)
		if err != nil || user == nil {
			continue
		}
		if user.TTL <= 0 {
			continue
		}
		var sev Severity
		switch {
		case user.TTL <= a.criticalTTL:
			sev = SeverityCritical
		case user.TTL <= a.warningTTL:
			sev = SeverityWarning
		default:
			continue
		}
		alerts = append(alerts, &Alert{
			Path:      fmt.Sprintf("okta/users/%s", username),
			ExpiresAt: time.Now().Add(user.TTL),
			Severity:  sev,
			Message:   fmt.Sprintf("Okta user %q TTL expires in %s", username, user.TTL.Round(time.Second)),
		})
	}
	return alerts, nil
}
