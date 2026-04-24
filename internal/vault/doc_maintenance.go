// Package vault provides maintenance mode monitoring for HashiCorp Vault.
//
// # Maintenance Monitoring
//
// The MaintenanceChecker polls the /v1/sys/maintenance endpoint to determine
// whether a Vault node is currently in maintenance mode.
//
// The MaintenanceAlerter wraps the checker and produces a MaintenanceAlert
// with SeverityCritical whenever maintenance mode is detected, allowing
// operators to integrate with any Notifier implementation.
//
// Example usage:
//
//	checker, err := vault.NewMaintenanceChecker(client)
//	if err != nil { ... }
//
//	alerter, err := vault.NewMaintenanceAlerter(checker, "https://vault.prod:8200")
//	if err != nil { ... }
//
//	alert, err := alerter.Evaluate()
//	if alert != nil {
//	    notifier.Send(ctx, alert.String(), alert.Severity)
//	}
package vault
