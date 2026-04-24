package vault

import (
	"fmt"
	"time"
)

// MaintenanceAlert is raised when a Vault node enters maintenance mode.
type MaintenanceAlert struct {
	NodeAddress string
	DetectedAt  time.Time
	Severity    string
}

// String returns a human-readable description of the alert.
func (a *MaintenanceAlert) String() string {
	return fmt.Sprintf("[%s] Vault node %s is in maintenance mode (detected %s)",
		a.Severity, a.NodeAddress, a.DetectedAt.Format(time.RFC3339))
}

// MaintenanceAlerter evaluates MaintenanceStatus and emits alerts.
type MaintenanceAlerter struct {
	checker *MaintenanceChecker
	address string
}

// NewMaintenanceAlerter constructs a MaintenanceAlerter.
func NewMaintenanceAlerter(checker *MaintenanceChecker, address string) (*MaintenanceAlerter, error) {
	if checker == nil {
		return nil, fmt.Errorf("maintenance checker must not be nil")
	}
	if address == "" {
		address = "unknown"
	}
	return &MaintenanceAlerter{checker: checker, address: address}, nil
}

// Evaluate fetches the current status and returns an alert if maintenance is active.
func (ma *MaintenanceAlerter) Evaluate() (*MaintenanceAlert, error) {
	status, err := ma.checker.Status()
	if err != nil {
		return nil, fmt.Errorf("evaluating maintenance status: %w", err)
	}
	if !status.IsInMaintenance() {
		return nil, nil
	}
	return &MaintenanceAlert{
		NodeAddress: ma.address,
		DetectedAt:  status.RetrievedAt,
		Severity:    SeverityCritical,
	}, nil
}
