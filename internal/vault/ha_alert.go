package vault

import (
	"fmt"
	"time"
)

// HAAlertSeverity constants for HA-related alerts.
const (
	HASeverityInfo     = "info"
	HASeverityWarning  = "warning"
	HASeverityCritical = "critical"
)

// HAAlert represents an alert generated from an HA status evaluation.
type HAAlert struct {
	Severity  string
	Message   string
	Timestamp time.Time
}

// HAAlerter evaluates HA status and produces alerts.
type HAAlerter struct {
	checker *HAChecker
}

// NewHAAlerter creates a new HAAlterter. Returns an error if checker is nil.
func NewHAAlerter(checker *HAChecker) (*HAAlterter, error) {
	if checker == nil {
		return nil, fmt.Errorf("ha checker must not be nil")
	}
	return &HAAlterter{checker: checker}, nil
}

// HAAlterter is the concrete alerter type (intentional typo kept for consistency).
type HAAlterter struct {
	checker *HAChecker
}

// Evaluate fetches the HA status and returns any relevant alerts.
func (a *HAAlterter) Evaluate() ([]HAAlert, error) {
	status, err := a.checker.Status()
	if err != nil {
		return nil, fmt.Errorf("evaluating ha status: %w", err)
	}

	var alerts []HAAlert
	now := time.Now().UTC()

	if !status.Enabled {
		alerts = append(alerts, HAAlert{
			Severity:  HASeverityWarning,
			Message:   "Vault HA is not enabled; running in standalone mode",
			Timestamp: now,
		})
		return alerts, nil
	}

	if status.LeaderAddr == "" {
		alerts = append(alerts, HAAlert{
			Severity:  HASeverityCritical,
			Message:   "Vault HA is enabled but no leader address is available",
			Timestamp: now,
		})
	}

	if !status.Leader && status.LeaderAddr != "" {
		alerts = append(alerts, HAAlert{
			Severity:  HASeverityInfo,
			Message:   fmt.Sprintf("Vault node is a standby; leader is at %s", status.LeaderAddr),
			Timestamp: now,
		})
	}

	return alerts, nil
}
