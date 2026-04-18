package vault

import (
	"errors"
	"fmt"
	"time"
)

// WrappingAlerter evaluates wrapping tokens and raises alerts when they are near expiry.
type WrappingAlerter struct {
	manager    *WrappingManager
	thresholds []time.Duration
}

// DefaultWrappingThresholds are the default TTL thresholds for wrapping token alerts.
var DefaultWrappingThresholds = []time.Duration{
	5 * time.Minute,
	1 * time.Minute,
}

// NewWrappingAlerter creates a new WrappingAlerter with optional custom thresholds.
func NewWrappingAlerter(manager *WrappingManager, thresholds []time.Duration) (*WrappingAlerter, error) {
	if manager == nil {
		return nil, errors.New("wrapping manager must not be nil")
	}
	if len(thresholds) == 0 {
		thresholds = DefaultWrappingThresholds
	}
	return &WrappingAlerter{manager: manager, thresholds: thresholds}, nil
}

// Evaluate checks the given wrapping token and returns an Alert if it is near or past expiry.
func (wa *WrappingAlerter) Evaluate(w *WrappedSecret) (*Alert, error) {
	if w == nil {
		return nil, errors.New("wrapped secret must not be nil")
	}

	if w.IsExpired() {
		return &Alert{
			Path:      fmt.Sprintf("wrapping/%s", w.Accessor),
			Message:   "wrapping token has expired",
			Severity:  SeverityCritical,
			ExpiresAt: w.CreatedAt.Add(w.TTL),
		}, nil
	}

	remaining := w.TimeUntilExpiry()
	for _, threshold := range wa.thresholds {
		if remaining <= threshold {
			sev := severityFromTTL(remaining)
			return &Alert{
				Path:      fmt.Sprintf("wrapping/%s", w.Accessor),
				Message:   fmt.Sprintf("wrapping token expires in %s", remaining.Round(time.Second)),
				Severity:  sev,
				ExpiresAt: w.CreatedAt.Add(w.TTL),
			}, nil
		}
	}
	return nil, nil
}
