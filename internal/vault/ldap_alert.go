package vault

import (
	"errors"
	"fmt"
	"time"
)

// LDAPAlerter evaluates LDAP roles and emits alerts for expiring entries.
type LDAPAlerter struct {
	scanner    *LDAPScanner
	warningTTL time.Duration
	criticalTTL time.Duration
}

// NewLDAPAlerter creates a new LDAPAlerter with given thresholds.
func NewLDAPAlerter(s *LDAPScanner, warning, critical time.Duration) (*LDAPAlerter, error) {
	if s == nil {
		return nil, errors.New("ldap scanner is required")
	}
	if warning == 0 {
		warning = 72 * time.Hour
	}
	if critical == 0 {
		critical = 24 * time.Hour
	}
	return &LDAPAlerter{scanner: s, warningTTL: warning, criticalTTL: critical}, nil
}

// Evaluate lists all LDAP roles and returns alerts for those nearing expiry.
func (a *LDAPAlerter) Evaluate() ([]*Alert, error) {
	names, err := a.scanner.ListRoles()
	if err != nil {
		return nil, fmt.Errorf("ldap alerter evaluate: %w", err)
	}
	var alerts []*Alert
	for _, name := range names {
		role, err := a.scanner.GetRole(name)
		if err != nil || role.TTL == 0 {
			continue
		}
		ttl := role.TimeUntilExpiry()
		var sev Severity
		switch {
		case ttl <= a.criticalTTL:
			sev = SeverityCritical
		case ttl <= a.warningTTL:
			sev = SeverityWarning
		default:
			continue
		}
		alerts = append(alerts, &Alert{
			Path:      fmt.Sprintf("auth/%s/groups/%s", a.scanner.mount, name),
			TTL:       ttl,
			Severity:  sev,
			Message:   fmt.Sprintf("LDAP role %q expires in %s", name, ttl.Round(time.Second)),
			ExpiresAt: time.Now().Add(ttl),
		})
	}
	return alerts, nil
}
