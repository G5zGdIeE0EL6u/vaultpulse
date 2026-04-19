package vault

import (
	"fmt"
	"time"
)

// AppRoleAlerter evaluates AppRole roles and raises alerts for short TTLs.
type AppRoleAlerter struct {
	scanner         *AppRoleScanner
	warningThreshold  time.Duration
	criticalThreshold time.Duration
}

// NewAppRoleAlerter creates an AppRoleAlerter with configurable thresholds.
func NewAppRoleAlerter(s *AppRoleScanner, warning, critical time.Duration) (*AppRoleAlerter, error) {
	if s == nil {
		return nil, fmt.Errorf("approle alerter: scanner must not be nil")
	}
	if warning == 0 {
		warning = 72 * time.Hour
	}
	if critical == 0 {
		critical = 24 * time.Hour
	}
	return &AppRoleAlerter{scanner: s, warningThreshold: warning, criticalThreshold: critical}, nil
}

// Evaluate lists all AppRoles and returns alerts for roles whose SecretIDTTL is below thresholds.
func (a *AppRoleAlerter) Evaluate() ([]*Alert, error) {
	roles, err := a.scanner.ListRoles()
	if err != nil {
		return nil, err
	}
	var alerts []*Alert
	for _, name := range roles {
		info, err := a.scanner.GetRole(name)
		if err != nil || info == nil {
			continue
		}
		ttl := info.SecretIDTTL
		if ttl <= 0 {
			continue
		}
		var sev string
		switch {
		case ttl <= a.criticalThreshold:
			sev = SeverityCritical
		case ttl <= a.warningThreshold:
			sev = SeverityWarning
		default:
			continue
		}
		alerts = append(alerts, &Alert{
			Path:      fmt.Sprintf("%s/role/%s", a.scanner.mount, name),
			TTL:       ttl,
			Severity:  sev,
			ExpiresAt: time.Now().Add(ttl),
		})
	}
	return alerts, nil
}
