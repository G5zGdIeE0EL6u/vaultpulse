// Package vault provides AppRole authentication engine scanning and alerting
// for the vaultpulse monitoring CLI.
//
// # AppRole Scanner
//
// NewAppRoleScanner creates a scanner that lists and retrieves AppRole
// configurations from a given Vault mount path (default: "approle").
//
// # AppRole Alerter
//
// NewAppRoleAlerter wraps an AppRoleScanner and evaluates each role's
// max_ttl against configurable thresholds, emitting Alert values with
// an appropriate Severity (Warning or Critical).
//
// Example usage:
//
//	scanner := vault.NewAppRoleScanner(client, "approle")
//	alerter := vault.NewAppRoleAlerter(scanner, nil) // uses defaults
//	alerts, err := alerter.EvaluateAll()
package vault
