// Package vault provides secret store scanning and alerting for Vault KV mounts.
//
// # SecretStore
//
// The SecretStore feature allows VaultPulse to enumerate secrets stored in
// a Vault KV v2 mount and evaluate their expiry metadata.
//
// Usage:
//
//	scanner := vault.NewSecretStoreScanner(client, "secret")
//	entries, err := scanner.ListEntries("apps")
//
//	alerter := vault.NewSecretStoreAlerter(scanner, vault.DefaultSecretStoreThresholds())
//	alerts := alerter.Evaluate(entries)
//
// Thresholds can be customised:
//
//	th := vault.SecretStoreThresholds{
//		Warning:  48 * time.Hour,
//		Critical: 12 * time.Hour,
//	}
package vault
