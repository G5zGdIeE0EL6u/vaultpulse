package vault

import "fmt"

// ReplicationAlert represents an alert raised for a replication issue.
type ReplicationAlert struct {
	Severity string
	Message  string
}

// ReplicationAlerter evaluates replication status and produces alerts.
type ReplicationAlerter struct {
	checker *ReplicationChecker
}

// NewReplicationAlerter creates a new ReplicationAlerter.
func NewReplicationAlerter(rc *ReplicationChecker) (*ReplicationAlerter, error) {
	if rc == nil {
		return nil, fmt.Errorf("replication checker must not be nil")
	}
	return &ReplicationAlerter{checker: rc}, nil
}

// Evaluate fetches replication status and returns any relevant alerts.
func (ra *ReplicationAlerter) Evaluate() ([]ReplicationAlert, error) {
	st, err := ra.checker.Status()
	if err != nil {
		return nil, fmt.Errorf("fetching replication status: %w", err)
	}

	var alerts []ReplicationAlert

	if !st.Connected {
		alerts = append(alerts, ReplicationAlert{
			Severity: "critical",
			Message:  "vault replication is not connected",
		})
	}

	if st.DRMode == "secondary" && st.LastWAL == 0 {
		alerts = append(alerts, ReplicationAlert{
			Severity: "warning",
			Message:  "DR secondary has no WAL progress",
		})
	}

	if st.PerformanceMode == "secondary" && !st.Connected {
		alerts = append(alerts, ReplicationAlert{
			Severity: "critical",
			Message:  "performance secondary is disconnected",
		})
	}

	return alerts, nil
}
