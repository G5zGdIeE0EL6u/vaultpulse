// Package vault provides support for scanning and alerting on Vault token roles.
//
// # Token Role Scanner
//
// TokenRoleScanner lists all token roles configured under auth/token/roles
// and retrieves their configuration, including TTL and renewal settings.
//
// Example usage:
//
//	scanner, err := vault.NewTokenRoleScanner(client)
//	if err != nil {
//		log.Fatal(err)
//	}
//	roles, err := scanner.ListRoles()
//
// # Token Role Alerter
//
// TokenRoleAlerter evaluates each token role's explicit_max_ttl against
// configurable warning and critical thresholds, emitting Alerts for roles
// that are nearing expiry.
//
// Default thresholds:
//   - Warning:  72 hours
//   - Critical: 24 hours
//
// Roles with an explicit_max_ttl of zero are considered non-expiring and
// are silently skipped.
package vault
