package vault

import (
	"fmt"
	"time"
)

// AppRoleThreshold defines a TTL boundary and severity for AppRole alerting.
type AppRoleThreshold struct {
	MaxTTL   time.Duration
	Severity Severity
}

// DefaultAppRoleThresholds provides sensible default alerting thresholds.
var DefaultAppRoleThresholds = []AppRoleThreshold{
	{MaxTTL: 24 * time.Hour, Severity: SeverityCritical},
	{MaxTTL: 72 * time.Hour, Severity: SeverityWarning},
}

// AppRoleAlerter evaluates AppRole configurations and emits alerts.
type AppRoleAlerter struct {
	scanner    *AppRoleScanner
	thresholds []AppRoleThreshold
}

// NewAppRoleAlerter creates an AppRoleAlerter. Returns nil if scanner is nil.
func NewAppRoleAlerter(scanner *AppRoleScanner, thresholds []AppRoleThreshold) *AppRoleAlerter {
	if scanner == nil {
		return nil
	}
	if len(thresholds) == 0 {
		thresholds = DefaultAppRoleThresholds
	}
	return &AppRoleAlerter{
		scanner:    scanner,
		thresholds: thresholds,
	}
}

// EvaluateRole checks a single AppRoleInfo against configured thresholds.
func (a *AppRoleAlerter) EvaluateRole(role AppRoleInfo) []Alert {
	var alerts []Alert
	if role.MaxTTL <= 0 {
		return alerts
	}
	for _, th := range a.thresholds {
		if role.MaxTTL <= th.MaxTTL {
			alerts = append(alerts, Alert{
				Path:     fmt.Sprintf("approle/role/%s", role.Name),
				Message:  fmt.Sprintf("AppRole %q max_ttl %s is at or below threshold %s", role.Name, role.MaxTTL, th.MaxTTL),
				Severity: th.Severity,
				Expiry:   time.Now().Add(role.MaxTTL),
			})
			break
		}
	}
	return alerts
}

// EvaluateAll scans all roles and returns aggregated alerts.
func (a *AppRoleAlerter) EvaluateAll() ([]Alert, error) {
	roles, err := a.scanner.ListRoles()
	if err != nil {
		return nil, fmt.Errorf("approle alerter: list roles: %w", err)
	}
	var all []Alert
	for _, r := range roles {
		all = append(all, a.EvaluateRole(r)...)
	}
	return all, nil
}
