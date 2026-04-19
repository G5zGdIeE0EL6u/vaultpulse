// Package vault provides Okta auth method scanning and alerting.
//
// The OktaScanner connects to a HashiCorp Vault instance and enumerates
// users configured under the Okta auth mount. It retrieves per-user TTL,
// group memberships, and policy assignments.
//
// The OktaAlerter wraps OktaScanner and evaluates each user's remaining
// TTL against configurable warning and critical thresholds, emitting
// structured Alert values that can be forwarded to any Notifier.
//
// Example usage:
//
//	scanner := vault.NewOktaScanner(client, "okta")
//	alerter := vault.NewOktaAlerter(scanner, 72*time.Hour, 24*time.Hour)
//	alerts, err := alerter.Evaluate()
package vault
