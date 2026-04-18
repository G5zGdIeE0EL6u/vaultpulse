package vault

import (
	"fmt"
	"time"
)

// CertAlertThreshold defines when to raise alerts for expiring certificates.
type CertAlertThreshold struct {
	Critical time.Duration
	Warning  time.Duration
}

// DefaultCertAlertThresholds returns sensible defaults.
func DefaultCertAlertThresholds() CertAlertThreshold {
	return CertAlertThreshold{
		Critical: 7 * 24 * time.Hour,
		Warning:  30 * 24 * time.Hour,
	}
}

// CertAlerter evaluates certificate expiry and produces alerts.
type CertAlerter struct {
	scanner    *CertScanner
	thresholds CertAlertThreshold
}

// NewCertAlerter creates a CertAlerter with the given scanner and thresholds.
func NewCertAlerter(scanner *CertScanner, thresholds CertAlertThreshold) (*CertAlerter, error) {
	if scanner == nil {
		return nil, fmt.Errorf("cert scanner must not be nil")
	}
	return &CertAlerter{scanner: scanner, thresholds: thresholds}, nil
}

// Evaluate checks a CertInfo and returns an Alert if expiry is near, or nil.
func (a *CertAlerter) Evaluate(cert *CertInfo) *Alert {
	if cert == nil || cert.Revoked {
		return nil
	}
	ttl := cert.TimeUntilExpiry()
	var severity Severity
	switch {
	case ttl <= a.thresholds.Critical:
		severity = SeverityCritical
	case ttl <= a.thresholds.Warning:
		severity = SeverityWarning
	default:
		return nil
	}
	return &Alert{
		Path:      fmt.Sprintf("pki/cert/%s", cert.Serial),
		Message:   fmt.Sprintf("certificate %s (%s) expires in %s", cert.Serial, cert.CommonName, ttl.Round(time.Second)),
		Severity:  severity,
		ExpiresAt: cert.Expiry,
	}
}
