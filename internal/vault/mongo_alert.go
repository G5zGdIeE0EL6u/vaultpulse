package vault

import (
	"fmt"
	"time"
)

// MongoAlerter evaluates MongoDB roles and emits alerts based on TTL thresholds.
type MongoAlerter struct {
	scanner         *MongoScanner
	warnThreshold   time.Duration
	critThreshold   time.Duration
}

// NewMongoAlerter creates a MongoAlerter. Returns error if scanner is nil.
func NewMongoAlerter(scanner *MongoScanner, warn, crit time.Duration) (*MongoAlerter, error) {
	if scanner == nil {
		return nil, fmt.Errorf("mongo alerter: scanner must not be nil")
	}
	if warn == 0 {
		warn = 72 * time.Hour
	}
	if crit == 0 {
		crit = 24 * time.Hour
	}
	return &MongoAlerter{scanner: scanner, warnThreshold: warn, critThreshold: crit}, nil
}

// Evaluate lists all roles and returns alerts for those with low MaxTTL.
func (a *MongoAlerter) Evaluate() ([]*Alert, error) {
	names, err := a.scanner.ListRoles()
	if err != nil {
		return nil, err
	}
	var alerts []*Alert
	for _, name := range names {
		role, err := a.scanner.GetRole(name)
		if err != nil || role == nil {
			continue
		}
		if role.MaxTTL <= 0 {
			continue
		}
		var sev Severity
		switch {
		case role.MaxTTL <= a.critThreshold:
			sev = SeverityCritical
		case role.MaxTTL <= a.warnThreshold:
			sev = SeverityWarning
		default:
			continue
		}
		alerts = append(alerts, &Alert{
			Path:      fmt.Sprintf("%s/roles/%s", a.scanner.mount, name),
			Severity:  sev,
			ExpiresAt: time.Now().Add(role.MaxTTL),
			Message:   fmt.Sprintf("MongoDB role %q MaxTTL expires in %s", name, role.MaxTTL.Round(time.Second)),
		})
	}
	return alerts, nil
}
