package vault

import (
	"fmt"
	"time"
)

// TelemetryThresholds defines alert thresholds for telemetry counters.
type TelemetryThresholds struct {
	MaxLeaseCount   int64
	MaxErrorCount   int64
	MaxTokenCount   int64
}

// DefaultTelemetryThresholds returns sensible production defaults.
func DefaultTelemetryThresholds() TelemetryThresholds {
	return TelemetryThresholds{
		MaxLeaseCount: 50_000,
		MaxErrorCount: 500,
		MaxTokenCount: 10_000,
	}
}

// TelemetryAlerter evaluates a TelemetrySample against configured thresholds.
type TelemetryAlerter struct {
	collector  *TelemetryCollector
	thresholds TelemetryThresholds
}

// NewTelemetryAlerter creates a TelemetryAlerter. Returns error if collector is nil.
func NewTelemetryAlerter(c *TelemetryCollector, t TelemetryThresholds) (*TelemetryAlerter, error) {
	if c == nil {
		return nil, fmt.Errorf("telemetry alerter: collector must not be nil")
	}
	return &TelemetryAlerter{collector: c, thresholds: t}, nil
}

// Evaluate collects a sample and returns Alerts for any breached threshold.
func (ta *TelemetryAlerter) Evaluate() ([]*Alert, error) {
	sample, err := ta.collector.Collect()
	if err != nil {
		return nil, fmt.Errorf("telemetry alerter: collect: %w", err)
	}

	var alerts []*Alert
	check := func(label string, value, max int64) {
		if max <= 0 || value <= max {
			return
		}
		alerts = append(alerts, &Alert{
			Path:      "sys/metrics",
			Message:   fmt.Sprintf("%s=%d exceeds threshold %d", label, value, max),
			Severity:  SeverityWarning,
			ExpiresAt: time.Now().Add(5 * time.Minute),
		})
	}

	check("lease_count", sample.LeaseCount, ta.thresholds.MaxLeaseCount)
	check("error_count", sample.ErrorCount, ta.thresholds.MaxErrorCount)
	check("token_count", sample.TokenCount, ta.thresholds.MaxTokenCount)
	return alerts, nil
}
