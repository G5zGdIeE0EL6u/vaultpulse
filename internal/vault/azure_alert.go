package vault

import (
	"fmt"
	"time"
)

// AzureAlerter evaluates Azure roles and emits alerts.
type AzureAlerter struct {
	scanner    *AzureScanner
	warningTTL time.Duration
	criticalTTL time.Duration
}

// NewAzureAlerter creates an AzureAlerter with default thresholds.
func NewAzureAlerter(scanner *AzureScanner) (*AzureAlerter, error) {
	if scanner == nil {
		return nil, fmt.Errorf("azure alerter: nil scanner")
	}
	return &AzureAlerter{
		scanner:     scanner,
		warningTTL:  72 * time.Hour,
		criticalTTL: 24 * time.Hour,
	}, nil
}

// Evaluate lists all Azure roles and returns alerts for expiring ones.
func (a *AzureAlerter) Evaluate() ([]*Alert, error) {
	names, err := a.scanner.ListRoles()
	if err != nil {
		return nil, fmt.Errorf("azure alerter: list: %w", err)
	}
	var alerts []*Alert
	for _, name := range names {
		role, err := a.scanner.GetRole(name)
		if err != nil || role == nil {
			continue
		}
		if role.TTL <= 0 {
			continue
		}
		var sev Severity
		switch {
		case role.TTL <= a.criticalTTL:
			sev = SeverityCritical
		case role.TTL <= a.warningTTL:
			sev = SeverityWarning
		default:
			continue
		}
		alerts = append(alerts, &Alert{
			Path:      fmt.Sprintf("%s/roles/%s", a.scanner.mount, name),
			TTL:       role.TTL,
			ExpiresAt: time.Now().Add(role.TTL),
			Severity:  sev,
		})
	}
	return alerts, nil
}
