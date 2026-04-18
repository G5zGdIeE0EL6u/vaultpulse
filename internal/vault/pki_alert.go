package vault

import (
	"fmt"
	"time"
)

// PKIAlerter evaluates PKI roles and raises alerts for short-lived MaxTTLs.
type PKIAlerter struct {
	scanner          *PKIScanner
	minMaxTTL        time.Duration
	warningThreshold time.Duration
}

// NewPKIAlerter creates a PKIAlerter. Returns nil if scanner is nil.
func NewPKIAlerter(scanner *PKIScanner, minMaxTTL, warningThreshold time.Duration) *PKIAlerter {
	if scanner == nil {
		return nil
	}
	if minMaxTTL == 0 {
		minMaxTTL = 24 * time.Hour
	}
	if warningThreshold == 0 {
		warningThreshold = 72 * time.Hour
	}
	return &PKIAlerter{
		scanner:          scanner,
		minMaxTTL:        minMaxTTL,
		warningThreshold: warningThreshold,
	}
}

// Evaluate lists all PKI roles and returns alerts for those with low MaxTTL.
func (a *PKIAlerter) Evaluate() ([]*Alert, error) {
	names, err := a.scanner.ListRoles()
	if err != nil {
		return nil, err
	}
	var alerts []*Alert
	for _, name := range names {
		role, err := a.scanner.GetRole(name)
		if err != nil || role.MaxTTL == 0 {
			continue
		}
		if role.MaxTTL <= a.minMaxTTL {
			alerts = append(alerts, &Alert{
				Secret:   fmt.Sprintf("pki/role/%s", name),
				TTL:      role.MaxTTL,
				Severity: SeverityCritical,
				Message:  fmt.Sprintf("PKI role %q max_ttl %s is critically low", name, role.MaxTTL),
			})
		} else if role.MaxTTL <= a.warningThreshold {
			alerts = append(alerts, &Alert{
				Secret:   fmt.Sprintf("pki/role/%s", name),
				TTL:      role.MaxTTL,
				Severity: SeverityWarning,
				Message:  fmt.Sprintf("PKI role %q max_ttl %s is below warning threshold", name, role.MaxTTL),
			})
		}
	}
	return alerts, nil
}
