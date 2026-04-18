package vault

import (
	"fmt"
	"time"
)

// SSHAlerter evaluates SSH roles and raises alerts for short-lived or misconfigured roles.
type SSHAlerter struct {
	scanner     *SSHScanner
	minTTL      time.Duration
	minMaxTTL   time.Duration
}

// NewSSHAlerter creates an SSHAlerter with the given scanner and thresholds.
// Returns an error if scanner is nil.
func NewSSHAlerter(scanner *SSHScanner, minTTL, minMaxTTL time.Duration) (*SSHAlerter, error) {
	if scanner == nil {
		return nil, fmt.Errorf("ssh alerter: scanner must not be nil")
	}
	if minTTL == 0 {
		minTTL = 10 * time.Minute
	}
	if minMaxTTL == 0 {
		minMaxTTL = time.Hour
	}
	return &SSHAlerter{scanner: scanner, minTTL: minTTL, minMaxTTL: minMaxTTL}, nil
}

// SSHAlert describes an issue found with an SSH role.
type SSHAlert struct {
	Role    string
	Message string
	Severity string
}

// Evaluate lists all SSH roles and returns alerts for roles that violate thresholds.
func (a *SSHAlerter) Evaluate() ([]SSHAlert, error) {
	names, err := a.scanner.ListRoles()
	if err != nil {
		return nil, fmt.Errorf("ssh alerter: list roles: %w", err)
	}
	var alerts []SSHAlert
	for _, name := range names {
		role, err := a.scanner.GetRole(name)
		if err != nil {
			alerts = append(alerts, SSHAlert{
				Role:     name,
				Message:  fmt.Sprintf("failed to fetch role: %v", err),
				Severity: "warning",
			})
			continue
		}
		if role.TTL > 0 && role.TTL < a.minTTL {
			alerts = append(alerts, SSHAlert{
				Role:     name,
				Message:  fmt.Sprintf("TTL %s is below minimum %s", role.TTL, a.minTTL),
				Severity: "warning",
			})
		}
		if role.MaxTTL > 0 && role.MaxTTL < a.minMaxTTL {
			alerts = append(alerts, SSHAlert{
				Role:     name,
				Message:  fmt.Sprintf("MaxTTL %s is below minimum %s", role.MaxTTL, a.minMaxTTL),
				Severity: "critical",
			})
		}
	}
	return alerts, nil
}
