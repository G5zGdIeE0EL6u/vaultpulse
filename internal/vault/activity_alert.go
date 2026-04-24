package vault

import (
	"fmt"
	"time"
)

// ActivityAlert represents an alert generated from Vault activity log analysis.
type ActivityAlert struct {
	Message   string
	Severity  string
	Timestamp time.Time
}

// ActivityAlerter evaluates Vault activity summaries and emits alerts
// when client counts or entity counts exceed configured thresholds.
type ActivityAlerter struct {
	checker             *ActivityChecker
	ClientCountWarning  int
	ClientCountCritical int
	EntityCountWarning  int
	EntityCountCritical int
}

// NewActivityAlerter creates an ActivityAlerter with the given ActivityChecker
// and default thresholds. Returns nil if checker is nil.
func NewActivityAlerter(checker *ActivityChecker) *ActivityAlerter {
	if checker == nil {
		return nil
	}
	return &ActivityAlerter{
		checker:             checker,
		ClientCountWarning:  500,
		ClientCountCritical: 1000,
		EntityCountWarning:  300,
		EntityCountCritical: 700,
	}
}

// Evaluate fetches the current activity summary and returns any alerts
// triggered by high client or entity counts. Returns an empty slice if
// all metrics are within acceptable bounds.
func (a *ActivityAlerter) Evaluate() ([]*ActivityAlert, error) {
	if a == nil || a.checker == nil {
		return nil, fmt.Errorf("activity alerter or checker is nil")
	}

	summary, err := a.checker.GetSummary()
	if err != nil {
		return nil, fmt.Errorf("activity alerter: failed to get summary: %w", err)
	}
	if summary == nil {
		return nil, nil
	}

	var alerts []*ActivityAlert
	now := time.Now().UTC()

	// Evaluate distinct entity count
	switch {
	case summary.DistinctEntities >= a.EntityCountCritical:
		alerts = append(alerts, &ActivityAlert{
			Message:   fmt.Sprintf("distinct entity count %d exceeds critical threshold %d", summary.DistinctEntities, a.EntityCountCritical),
			Severity:  "critical",
			Timestamp: now,
		})
	case summary.DistinctEntities >= a.EntityCountWarning:
		alerts = append(alerts, &ActivityAlert{
			Message:   fmt.Sprintf("distinct entity count %d exceeds warning threshold %d", summary.DistinctEntities, a.EntityCountWarning),
			Severity:  "warning",
			Timestamp: now,
		})
	}

	// Evaluate non-entity token count as a proxy for total client activity
	switch {
	case summary.NonEntityTokens >= a.ClientCountCritical:
		alerts = append(alerts, &ActivityAlert{
			Message:   fmt.Sprintf("non-entity token count %d exceeds critical threshold %d", summary.NonEntityTokens, a.ClientCountCritical),
			Severity:  "critical",
			Timestamp: now,
		})
	case summary.NonEntityTokens >= a.ClientCountWarning:
		alerts = append(alerts, &ActivityAlert{
			Message:   fmt.Sprintf("non-entity token count %d exceeds warning threshold %d", summary.NonEntityTokens, a.ClientCountWarning),
			Severity:  "warning",
			Timestamp: now,
		})
	}

	return alerts, nil
}
