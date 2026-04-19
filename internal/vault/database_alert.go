package vault

import (
	"fmt"
	"time"
)

// DatabaseAlerter evaluates database secret engine roles and emits alerts
// when their default or max TTL values fall below configured thresholds.
type DatabaseAlerter struct {
	scanner    *DatabaseScanner
	warningTTL time.Duration
	criticalTTL time.Duration
}

// DefaultDatabaseAlertThresholds returns the default warning and critical
// TTL thresholds used by NewDatabaseAlerter when none are specified.
func DefaultDatabaseAlertThresholds() (warning, critical time.Duration) {
	return 72 * time.Hour, 24 * time.Hour
}

// NewDatabaseAlerter constructs a DatabaseAlerter with the given scanner and
// optional TTL thresholds. If warningTTL or criticalTTL are zero, defaults
// are applied.
func NewDatabaseAlerter(scanner *DatabaseScanner, warningTTL, criticalTTL time.Duration) (*DatabaseAlerter, error) {
	if scanner == nil {
		return nil, fmt.Errorf("database alerter: scanner must not be nil")
	}
	defWarn, defCrit := DefaultDatabaseAlertThresholds()
	if warningTTL == 0 {
		warningTTL = defWarn
	}
	if criticalTTL == 0 {
		criticalTTL = defCrit
	}
	return &DatabaseAlerter{
		scanner:     scanner,
		warningTTL:  warningTTL,
		criticalTTL: criticalTTL,
	}, nil
}

// Evaluate lists all roles from the configured database mount and returns an
// Alert for each role whose DefaultTTL is at or below the warning threshold.
// Roles with a zero DefaultTTL are skipped as they inherit engine defaults.
func (a *DatabaseAlerter) Evaluate(mount string) ([]*Alert, error) {
	roles, err := a.scanner.ListRoles(mount)
	if err != nil {
		return nil, fmt.Errorf("database alerter: list roles: %w", err)
	}

	var alerts []*Alert
	for _, name := range roles {
		role, err := a.scanner.GetRole(mount, name)
		if err != nil {
			// Log and continue so a single bad role doesn't abort the run.
			continue
		}
		if role.DefaultTTL == 0 {
			continue
		}

		ttl := role.DefaultTTL
		var severity Severity
		switch {
		case ttl <= a.criticalTTL:
			severity = SeverityCritical
		case ttl <= a.warningTTL:
			severity = SeverityWarning
		default:
			continue
		}

		alerts = append(alerts, &Alert{
			Path:      fmt.Sprintf("%s/roles/%s", mount, name),
			Message:   fmt.Sprintf("database role %q default TTL %s is below threshold", name, ttl),
			Severity:  severity,
			ExpiresAt: time.Now().Add(ttl),
		})
	}
	return alerts, nil
}
