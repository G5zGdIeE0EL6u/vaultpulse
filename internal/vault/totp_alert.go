package vault

import (
	"fmt"
	"time"
)

// TOTPAlerter raises alerts for TOTP keys that have an unusually short period,
// which may indicate misconfiguration.
type TOTPAlerter struct {
	scanner       *TOTPScanner
	minPeriod     int // seconds; keys with period < minPeriod trigger a warning
}

// NewTOTPAlerter creates a TOTPAlerter. minPeriod defaults to 30 if zero.
func NewTOTPAlerter(scanner *TOTPScanner, minPeriod int) (*TOTPAlerter, error) {
	if scanner == nil {
		return nil, fmt.Errorf("totp alerter: scanner must not be nil")
	}
	if minPeriod <= 0 {
		minPeriod = 30
	}
	return &TOTPAlerter{scanner: scanner, minPeriod: minPeriod}, nil
}

// Evaluate lists all TOTP keys and returns alerts for any with a period below
// the configured minimum.
func (a *TOTPAlerter) Evaluate() ([]*Alert, error) {
	names, err := a.scanner.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("totp alerter: list keys: %w", err)
	}

	var alerts []*Alert
	for _, name := range names {
		key, err := a.scanner.GetKey(name)
		if err != nil || key == nil {
			continue
		}
		if key.Period > 0 && key.Period < a.minPeriod {
			alerts = append(alerts, &Alert{
				Path:      fmt.Sprintf("%s/keys/%s", a.scanner.mount, name),
				Message:   fmt.Sprintf("TOTP key %q has short period %ds (min %ds)", name, key.Period, a.minPeriod),
				Severity:  SeverityWarning,
				ExpiresAt: time.Now().Add(time.Duration(key.Period) * time.Second),
			})
		}
	}
	return alerts, nil
}
