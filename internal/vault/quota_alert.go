package vault

import "fmt"

// QuotaAlert represents an alert raised for a quota approaching its limit.
type QuotaAlert struct {
	QuotaName string
	Path      string
	Rate      float64
	Severity  string
	Message   string
}

// QuotaAlerter evaluates quotas and raises alerts for low-rate quotas.
type QuotaAlerter struct {
	checker        *QuotaChecker
	WarnThreshold  float64 // alerts if rate <= this (warning)
	CritThreshold  float64 // alerts if rate <= this (critical)
}

// NewQuotaAlerter returns a QuotaAlerter with sensible defaults.
func NewQuotaAlerter(c *QuotaChecker) (*QuotaAlerter, error) {
	if c == nil {
		return nil, fmt.Errorf("quota checker must not be nil")
	}
	return &QuotaAlerter{
		checker:       c,
		WarnThreshold: 50.0,
		CritThreshold: 10.0,
	}, nil
}

// Evaluate lists all quotas and returns alerts for those below thresholds.
func (a *QuotaAlerter) Evaluate() ([]*QuotaAlert, error) {
	names, err := a.checker.ListQuotas()
	if err != nil {
		return nil, err
	}
	var alerts []*QuotaAlert
	for _, name := range names {
		info, err := a.checker.GetQuota(name)
		if err != nil || info == nil {
			continue
		}
		var severity string
		switch {
		case info.Rate <= a.CritThreshold:
			severity = "critical"
		case info.Rate <= a.WarnThreshold:
			severity = "warning"
		default:
			continue
		}
		alerts = append(alerts, &QuotaAlert{
			QuotaName: info.Name,
			Path:      info.Path,
			Rate:      info.Rate,
			Severity:  severity,
			Message:   fmt.Sprintf("quota %q on path %q has low rate: %.1f req/s", info.Name, info.Path, info.Rate),
		})
	}
	return alerts, nil
}
