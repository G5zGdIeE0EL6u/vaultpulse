package vault

import (
	"fmt"
	"time"
)

// AWSAlerter evaluates AWS credential leases and emits alerts.
type AWSAlerter struct {
	scanner    *AWSScanner
	warningTTL time.Duration
	criticalTTL time.Duration
}

// NewAWSAlerter creates a new AWSAlerter with default thresholds.
func NewAWSAlerter(scanner *AWSScanner) *AWSAlerter {
	if scanner == nil {
		return nil
	}
	return &AWSAlerter{
		scanner:     scanner,
		warningTTL:  72 * time.Hour,
		criticalTTL: 24 * time.Hour,
	}
}

// Evaluate checks an AWSCredential and returns an Alert if thresholds are breached.
func (a *AWSAlerter) Evaluate(cred *AWSCredential, role string) *Alert {
	if cred == nil {
		return nil
	}
	ttl := cred.TimeUntilExpiry()
	if ttl <= 0 {
		return &Alert{
			Path:     fmt.Sprintf("aws/creds/%s", role),
			Message:  fmt.Sprintf("AWS credential for role %q has expired", role),
			Severity: SeverityCritical,
			Expiry:   cred.LeaseExpiry,
		}
	}
	if ttl <= a.criticalTTL {
		return &Alert{
			Path:     fmt.Sprintf("aws/creds/%s", role),
			Message:  fmt.Sprintf("AWS credential for role %q expires in %s", role, ttl.Round(time.Minute)),
			Severity: SeverityCritical,
			Expiry:   cred.LeaseExpiry,
		}
	}
	if ttl <= a.warningTTL {
		return &Alert{
			Path:     fmt.Sprintf("aws/creds/%s", role),
			Message:  fmt.Sprintf("AWS credential for role %q expires in %s", role, ttl.Round(time.Minute)),
			Severity: SeverityWarning,
			Expiry:   cred.LeaseExpiry,
		}
	}
	return nil
}
