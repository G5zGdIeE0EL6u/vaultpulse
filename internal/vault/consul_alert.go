package vault

import (
	"fmt"
	"time"
)

// ConsulAlerter evaluates Consul roles and emits alerts.
type ConsulAlerter struct {
	scanner    *ConsulScanner
	warningTTL time.Duration
	criticalTTL time.Duration
}

// NewConsulAlerter creates a ConsulAlerter. Returns nil if scanner is nil.
func NewConsulAlerter(scanner *ConsulScanner, warning, critical time.Duration) *ConsulAlerter {
	if scanner == nil {
		return nil
	}
	if warning == 0 {
		warning = 7 * 24 * time.Hour
	}
	if critical == 0 {
		critical = 24 * time.Hour
	}
	return &ConsulAlerter{scanner: scanner, warningTTL: warning, criticalTTL: critical}
}

// Evaluate lists all roles and returns alerts for those with short or zero leases.
func (a *ConsulAlerter) Evaluate() ([]*Alert, error) {
	names, err := a.scanner.ListRoles()
	if err != nil {
		return nil, fmt.Errorf("consul alerter: %w", err)
	}
	var alerts []*Alert
	for _, name := range names {
		role, err := a.scanner.GetRole(name)
		if err != nil || role == nil {
			continue
		}
		if role.Lease <= 0 {
			continue
		}
		var sev Severity
		switch {
		case role.Lease <= a.criticalTTL:
			sev = SeverityCritical
		case role.Lease <= a.warningTTL:
			sev = SeverityWarning
		default:
			continue
		}
		alerts = append(alerts, &Alert{
			Path:      fmt.Sprintf("%s/roles/%s", a.scanner.mount, name),
			TTL:       role.Lease,
			Severity:  sev,
			ExpiresAt: time.Now().Add(role.Lease),
		})
	}
	return alerts, nil
}
