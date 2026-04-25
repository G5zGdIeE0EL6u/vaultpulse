// Package vault provides GCP KMS secrets engine scanning and alerting for
// VaultPulse.
//
// # GCP KMS
//
// The GCPKMSScanner connects to Vault's gcpkms secrets engine and retrieves
// key metadata including rotation periods and last-rotated timestamps.
//
// The GCPKMSAlerter wraps the scanner and emits Alert values for keys that are
// approaching or past their scheduled rotation window. Two configurable
// thresholds control alert severity:
//
//   - warning  – raised when TimeUntilRotation falls below the warning duration
//   - critical – raised when TimeUntilRotation falls below the critical duration
//     or the key is already overdue
//
// Example usage:
//
//	scanner, _ := vault.NewGCPKMSScanner(client, "gcpkms")
//	alerter, _ := vault.NewGCPKMSAlerter(scanner, 7*24*time.Hour, 24*time.Hour)
//	alerts, _ := alerter.Evaluate()
package vault
