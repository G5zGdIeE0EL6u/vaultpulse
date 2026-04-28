package vault

import (
	"fmt"
	"time"
)

// ControlGroupAlerter evaluates control group requests and emits alerts
// for requests that are expiring soon or have already expired.
type ControlGroupAlerter struct {
	scanner         *ControlGroupScanner
	warningThreshold time.Duration
	criticalThreshold time.Duration
}

// NewControlGroupAlerter creates a new ControlGroupAlerter.
// Returns nil if scanner is nil.
func NewControlGroupAlerter(scanner *ControlGroupScanner, warning, critical time.Duration) *ControlGroupAlerter {
	if scanner == nil {
		return nil
	}
	if warning == 0 {
		warning = 2 * time.Hour
	}
	if critical == 0 {
		critical = 30 * time.Minute
	}
	return &ControlGroupAlerter{
		scanner:          scanner,
		warningThreshold:  warning,
		criticalThreshold: critical,
	}
}

// Evaluate inspects the given accessor and returns an Alert if the request
// is expiring within the configured thresholds, or nil if it is healthy.
func (a *ControlGroupAlerter) Evaluate(accessor string) (*Alert, error) {
	req, err := a.scanner.GetRequest(accessor)
	if err != nil {
		return nil, err
	}

	ttl := req.TimeUntilExpiry()

	switch {
	case req.IsExpired():
		return &Alert{
			Path:      req.Path,
			Message:   fmt.Sprintf("control group request %s has expired", accessor),
			Severity:  SeverityCritical,
			ExpiresAt: req.ExpiresAt,
		}, nil
	case ttl <= a.criticalThreshold:
		return &Alert{
			Path:      req.Path,
			Message:   fmt.Sprintf("control group request %s expires in %s", accessor, ttl.Round(time.Second)),
			Severity:  SeverityCritical,
			ExpiresAt: req.ExpiresAt,
		}, nil
	case ttl <= a.warningThreshold:
		return &Alert{
			Path:      req.Path,
			Message:   fmt.Sprintf("control group request %s expires in %s", accessor, ttl.Round(time.Second)),
			Severity:  SeverityWarning,
			ExpiresAt: req.ExpiresAt,
		}, nil
	}
	return nil, nil
}
