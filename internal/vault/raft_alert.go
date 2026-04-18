package vault

import (
	"context"
	"fmt"
)

// RaftAlerter evaluates Raft cluster health and emits alerts.
type RaftAlerter struct {
	checker *RaftChecker
}

// NewRaftAlerter creates a RaftAlerter. Returns error if checker is nil.
func NewRaftAlerter(c *RaftChecker) (*RaftAlerter, error) {
	if c == nil {
		return nil, fmt.Errorf("raft alerter: checker must not be nil")
	}
	return &RaftAlerter{checker: c}, nil
}

// Evaluate fetches Raft status and returns alerts for unhealthy conditions.
func (a *RaftAlerter) Evaluate(ctx context.Context) ([]Alert, error) {
	status, err := a.checker.Status(ctx)
	if err != nil {
		return nil, err
	}

	var alerts []Alert

	leaders := 0
	for _, p := range status.Peers {
		if p.Leader {
			leaders++
		}
	}

	if leaders == 0 {
		alerts = append(alerts, Alert{
			Path:     "sys/storage/raft",
			Message:  "raft cluster has no leader",
			Severity: SeverityCritical,
		})
	} else if leaders > 1 {
		alerts = append(alerts, Alert{
			Path:     "sys/storage/raft",
			Message:  fmt.Sprintf("raft cluster has %d leaders (split-brain risk)", leaders),
			Severity: SeverityCritical,
		})
	}

	voters := 0
	for _, p := range status.Peers {
		if p.Voter {
			voters++
		}
	}
	if voters > 0 && voters%2 == 0 {
		alerts = append(alerts, Alert{
			Path:     "sys/storage/raft",
			Message:  fmt.Sprintf("raft cluster has even voter count (%d), quorum risk", voters),
			Severity: SeverityWarning,
		})
	}

	return alerts, nil
}
