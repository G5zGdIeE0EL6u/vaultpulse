package vault

import (
	"context"
	"fmt"
	"time"
)

// PolicyInfo holds metadata about a Vault policy and its associated secrets.
type PolicyInfo struct {
	Name      string
	Paths     []string
	FetchedAt time.Time
}

// PolicyChecker inspects Vault policies for secret paths.
type PolicyChecker struct {
	client *Client
}

// NewPolicyChecker creates a new PolicyChecker.
func NewPolicyChecker(c *Client) *PolicyChecker {
	return &PolicyChecker{client: c}
}

// GetPolicy retrieves a policy by name from Vault.
func (p *PolicyChecker) GetPolicy(ctx context.Context, name string) (*PolicyInfo, error) {
	if name == "" {
		return nil, fmt.Errorf("policy name must not be empty")
	}
	secret, err := p.client.vc.Logical().ReadWithContext(ctx, "sys/policy/"+name)
	if err != nil {
		return nil, fmt.Errorf("reading policy %q: %w", name, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("policy %q not found", name)
	}
	paths := extractPaths(secret.Data)
	return &PolicyInfo{
		Name:      name,
		Paths:     paths,
		FetchedAt: time.Now(),
	}, nil
}

// extractPaths pulls path keys from raw policy data.
func extractPaths(data map[string]interface{}) []string {
	raw, ok := data["paths"]
	if !ok {
		return nil
	}
	list, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	paths := make([]string, 0, len(list))
	for _, v := range list {
		if s, ok := v.(string); ok {
			paths = append(paths, s)
		}
	}
	return paths
}
