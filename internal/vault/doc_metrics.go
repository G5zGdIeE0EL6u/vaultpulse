// Package vault provides MetricsCollector and MetricsAlerter for monitoring
// HashiCorp Vault telemetry via the sys/metrics endpoint.
//
// # MetricsCollector
//
// MetricsCollector fetches the Prometheus-formatted metrics exposed by Vault
// and converts them into a slice of MetricPoint values.
//
// # MetricsAlerter
//
// MetricsAlerter wraps a MetricsCollector and evaluates the collected points
// to produce an Alert when Vault appears unhealthy (e.g., vault_up == 0 or
// the metrics endpoint is unreachable).
//
// Example usage:
//
//	client, _ := vault.NewClient(addr, token)
//	mc, _ := vault.NewMetricsCollector(client)
//	ma, _ := vault.NewMetricsAlerter(mc)
//	alert, err := ma.Evaluate()
package vault
