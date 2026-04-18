// Package vault provides LDAP auth backend scanning and alerting.
//
// # LDAP Module
//
// The LDAP module allows vaultpulse to inspect HashiCorp Vault's LDAP
// auth method for group role configurations, TTL values, and expiry.
//
// Usage:
//
//	scanner, err := vault.NewLDAPScanner(client, "ldap")
//	if err != nil { ... }
//
//	roles, err := scanner.ListRoles()
//	if err != nil { ... }
//
//	alerter, err := vault.NewLDAPAlerter(scanner, 72*time.Hour, 24*time.Hour)
//	if err != nil { ... }
//
//	alerts, err := alerter.Evaluate()
//	if err != nil { ... }
//
// Alerts are emitted for roles whose TTL falls within the warning or
// critical thresholds. Roles with a TTL of zero are skipped.
package vault
