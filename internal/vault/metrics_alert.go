package vault

import (
	"fmt"
	"time"
)

// MetricsAlerter evaluates collected MetricPoints and raises alerts
// when Vault appears unavailable.
type MetricsAlerter struct {
	collector *MetricsCollector
}

// NewMetricsAlerter creates a MetricsAlerter. Returns an error if collector is nil.
func NewMetricsAlerter(collector *MetricsCollector) (*MetricsAlerter, error) {
	if collector == nil {
		return nil, fmt.Errorf("metrics collector must not be nil")
	}
	return &MetricsAlerter{collector: collector}, nil
}

// Evaluate collects metrics and returns an Alert if Vault is unreachable.
// Returns nil when everything looks healthy.
func (ma *MetricsAlerter) Evaluate() (*Alert, error) {
	points, err := ma.collector.Collect()
	if err != nil {
		return &Alert{
			Path:      "sys/metrics",
			Message:   fmt.Sprintf("metrics collection failed: %v", err),
			Severity:  SeverityCritical,
			ExpiresAt: time.Now().UTC(),
		}, nil
	}

	for _, p := range points {
		if p.Name == "vault_up" && p.Value < 1 {
			return &Alert{
				Path:      "sys/metrics",
				Message:   "vault_up metric is zero — instance may be down",
				Severity:  SeverityCritical,
				ExpiresAt: time.Now().UTC(),
			}, nil
		}
	}
	return nil, nil
}
