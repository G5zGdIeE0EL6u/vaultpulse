package vault

import (
	"fmt"
	"time"
)

// IdentityAlerter evaluates identity entities and raises alerts for disabled
// or stale entities.
type IdentityAlerter struct {
	scanner      *IdentityScanner
	stalenessAge time.Duration
}

// NewIdentityAlerter creates a new IdentityAlerter.
// Returns nil if scanner is nil.
// stalenessAge defines how long since last update before an entity is considered stale.
func NewIdentityAlerter(scanner *IdentityScanner, stalenessAge time.Duration) *IdentityAlerter {
	if scanner == nil {
		return nil
	}
	if stalenessAge <= 0 {
		stalenessAge = 90 * 24 * time.Hour // 90 days default
	}
	return &IdentityAlerter{scanner: scanner, stalenessAge: stalenessAge}
}

// Evaluate lists all entities and returns alerts for disabled or stale ones.
func (a *IdentityAlerter) Evaluate() ([]Alert, error) {
	ids, err := a.scanner.ListEntities()
	if err != nil {
		return nil, fmt.Errorf("identity alerter: list: %w", err)
	}

	var alerts []Alert
	now := time.Now()

	for _, id := range ids {
		entity, err := a.scanner.GetEntity(id)
		if err != nil {
			continue
		}

		if entity.Disabled {
			alerts = append(alerts, Alert{
				Path:     "identity/entity/" + entity.ID,
				Message:  fmt.Sprintf("identity entity %q is disabled", entity.Name),
				Severity: SeverityWarning,
				ExpiresAt: entity.LastUpdateTime,
			})
			continue
		}

		age := now.Sub(entity.LastUpdateTime)
		if age > a.stalenessAge {
			alerts = append(alerts, Alert{
				Path:     "identity/entity/" + entity.ID,
				Message:  fmt.Sprintf("identity entity %q has not been updated in %s", entity.Name, age.Round(time.Hour)),
				Severity: SeverityInfo,
				ExpiresAt: entity.LastUpdateTime.Add(a.stalenessAge),
			})
		}
	}
	return alerts, nil
}
