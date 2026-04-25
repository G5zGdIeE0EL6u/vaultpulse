package vault

import (
	"fmt"
	"time"
)

// GCPKMSAlerter evaluates GCP KMS keys and raises alerts for keys due for rotation.
type GCPKMSAlerter struct {
	scanner           *GCPKMSScanner
	warningThreshold  time.Duration
	criticalThreshold time.Duration
}

// NewGCPKMSAlerter creates a new GCPKMSAlerter with the provided scanner.
// Returns an error if scanner is nil.
func NewGCPKMSAlerter(scanner *GCPKMSScanner, warning, critical time.Duration) (*GCPKMSAlerter, error) {
	if scanner == nil {
		return nil, fmt.Errorf("gcpkms alerter: scanner must not be nil")
	}
	if warning == 0 {
		warning = 7 * 24 * time.Hour
	}
	if critical == 0 {
		critical = 24 * time.Hour
	}
	return &GCPKMSAlerter{
		scanner:           scanner,
		warningThreshold:  warning,
		criticalThreshold: critical,
	}, nil
}

// Evaluate lists all GCP KMS keys and returns alerts for any that are due or
// approaching rotation.
func (a *GCPKMSAlerter) Evaluate() ([]*Alert, error) {
	keys, err := a.scanner.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("gcpkms alerter: list keys: %w", err)
	}

	var alerts []*Alert
	for _, name := range keys {
		key, err := a.scanner.GetKey(name)
		if err != nil || key == nil {
			continue
		}
		if key.RotationPeriod <= 0 {
			continue
		}
		ttl := key.TimeUntilRotation()
		var sev Severity
		switch {
		case ttl <= 0:
			sev = SeverityCritical
		case ttl <= a.criticalThreshold:
			sev = SeverityCritical
		case ttl <= a.warningThreshold:
			sev = SeverityWarning
		default:
			continue
		}
		alerts = append(alerts, &Alert{
			Path:     fmt.Sprintf("%s/keys/%s", a.scanner.mount, name),
			Message:  fmt.Sprintf("GCP KMS key %q rotation due in %s", name, ttl.Round(time.Second)),
			Severity: sev,
			Expiry:   key.LastRotated.Add(time.Duration(key.RotationPeriod) * time.Second),
		})
	}
	return alerts, nil
}
