package vault

import "fmt"

// ReplicationAlert holds a single replication-related alert.
type ReplicationAlert struct {
	Severity string
	Message  string
}

// ReplicationAlerter evaluates replication status and produces alerts.
type ReplicationAlerter struct{}

// NewReplicationAlerter returns a new ReplicationAlerter.
func NewReplicationAlerter() *ReplicationAlerter {
	return &ReplicationAlerter{}
}

// Evaluate inspects a ReplicationStatus and returns any alerts.
func (a *ReplicationAlerter) Evaluate(status *ReplicationStatus) []ReplicationAlert {
	if status == nil {
		return nil
	}

	var alerts []ReplicationAlert

	if status.DRMode != "disabled" && status.DRMode != "" {
		if status.DRState != "running" {
			alerts = append(alerts, ReplicationAlert{
				Severity: "warning",
				Message:  fmt.Sprintf("DR replication is in state %q (mode: %s)", status.DRState, status.DRMode),
			})
		}
	}

	if status.PerfMode != "disabled" && status.PerfMode != "" {
		if status.PerfState != "running" {
			alerts = append(alerts, ReplicationAlert{
				Severity: "warning",
				Message:  fmt.Sprintf("performance replication is in state %q (mode: %s)", status.PerfState, status.PerfMode),
			})
		}
	}

	return alerts
}
