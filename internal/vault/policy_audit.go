package vault

import (
	"context"
	"fmt"
	"time"
)

// PolicyAuditResult captures the result of auditing a policy's secret paths.
type PolicyAuditResult struct {
	Policy    string
	Path      string
	Alertable bool
	CheckedAt time.Time
}

// PolicyAuditor combines PolicyChecker and Scanner to audit secret paths
// referenced by a Vault policy.
type PolicyAuditor struct {
	checker *PolicyChecker
	scanner *Scanner
}

// NewPolicyAuditor creates a PolicyAuditor.
func NewPolicyAuditor(checker *PolicyChecker, scanner *Scanner) *PolicyAuditor {
	return &PolicyAuditor{checker: checker, scanner: scanner}
}

// Audit fetches the policy and scans each path for expiring secrets.
func (a *PolicyAuditor) Audit(ctx context.Context, policyName string) ([]PolicyAuditResult, error) {
	info, err := a.checker.GetPolicy(ctx, policyName)
	if err != nil {
		return nil, fmt.Errorf("policy audit: %w", err)
	}
	var results []PolicyAuditResult
	for _, path := range info.Paths {
		alerts, err := a.scanner.Scan(ctx, path)
		if err != nil {
			results = append(results, PolicyAuditResult{
				Policy:    policyName,
				Path:      path,
				Alertable: false,
				CheckedAt: time.Now(),
			})
			continue
		}
		results = append(results, PolicyAuditResult{
			Policy:    policyName,
			Path:      path,
			Alertable: len(alerts) > 0,
			CheckedAt: time.Now(),
		})
	}
	return results, nil
}
