// Package vault provides identity entity scanning and alerting for HashiCorp Vault.
//
// # Identity Entity Scanning
//
// The IdentityScanner type lists and retrieves identity entities from the
// Vault identity store via the /v1/identity/entity/id API.
//
// # Identity Alerting
//
// The IdentityAlerter evaluates entities and raises:
//   - SeverityWarning alerts for disabled entities
//   - SeverityInfo alerts for entities not updated within the configured
//     staleness window (default: 90 days)
//
// Example usage:
//
//	scanner := vault.NewIdentityScanner(client)
//	alerter := vault.NewIdentityAlerter(scanner, 60*24*time.Hour)
//	alerts, err := alerter.Evaluate()
package vault
