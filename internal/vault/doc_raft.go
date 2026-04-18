// Package vault provides Raft storage backend monitoring for HashiCorp Vault.
//
// # Raft Health Monitoring
//
// RaftChecker queries the /v1/sys/storage/raft/configuration endpoint to
// retrieve current cluster peer information including leader election state
// and voter membership.
//
// RaftAlerter evaluates the cluster state and raises:
//   - SeverityCritical when no leader is elected or multiple leaders exist.
//   - SeverityWarning  when an even number of voters creates quorum risk.
//
// Example usage:
//
//	client, _ := vault.NewClient(addr, token)
//	checker, _ := vault.NewRaftChecker(client)
//	alerter, _ := vault.NewRaftAlerter(checker)
//	alerts, err := alerter.Evaluate(ctx)
package vault
