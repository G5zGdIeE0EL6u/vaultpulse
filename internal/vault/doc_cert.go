// Package vault provides PKI certificate scanning and alerting for Vault-managed
// certificates.
//
// # Certificate Scanning
//
// CertScanner lists serial numbers and retrieves certificate metadata from a
// Vault PKI secrets engine mount (default: "pki").
//
// # Certificate Alerting
//
// CertAlerter evaluates CertInfo values against configurable thresholds and
// returns Alert values compatible with the rest of the vaultpulse alerting
// pipeline. Revoked certificates are silently skipped.
//
// # Usage
//
//	scanner, _ := vault.NewCertScanner(client, "pki")
//	alerter, _ := vault.NewCertAlerter(scanner, vault.DefaultCertAlertThresholds())
//	serials, _ := scanner.ListSerials()
//	for _, serial := range serials {
//		cert, _ := scanner.GetCert(serial)
//		if alert := alerter.Evaluate(cert); alert != nil {
//			// send alert
//		}
//	}
package vault
