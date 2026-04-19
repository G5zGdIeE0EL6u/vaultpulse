package vault

import (
	"fmt"
	"time"
)

// ConsulRole represents a Consul secrets engine role.
type ConsulRole struct {
	Name      string
	Lease     time.Duration
	TokenType string
	Policies  []string
}

// IsExpired returns true if the role lease is zero.
func (r *ConsulRole) IsExpired() bool {
	return r.Lease <= 0
}

// TimeUntilExpiry returns the lease duration.
func (r *ConsulRole) TimeUntilExpiry() time.Duration {
	return r.Lease
}

// ConsulScanner scans Consul secrets engine roles.
type ConsulScanner struct {
	client *Client
	mount  string
}

// NewConsulScanner creates a new ConsulScanner. Returns nil if client is nil.
func NewConsulScanner(client *Client, mount string) *ConsulScanner {
	if client == nil {
		return nil
	}
	if mount == "" {
		mount = "consul"
	}
	return &ConsulScanner{client: client, mount: mount}
}

// ListRoles returns all role names for the Consul mount.
func (s *ConsulScanner) ListRoles() ([]string, error) {
	path := fmt.Sprintf("%s/roles", s.mount)
	data, err := s.client.ListSecrets(path)
	if err != nil {
		return nil, fmt.Errorf("consul: list roles: %w", err)
	}
	keys, _ := data["keys"].([]interface{})
	var roles []string
	for _, k := range keys {
		if name, ok := k.(string); ok {
			roles = append(roles, name)
		}
	}
	return roles, nil
}

// GetRole retrieves a single Consul role by name.
func (s *ConsulScanner) GetRole(name string) (*ConsulRole, error) {
	if name == "" {
		return nil, fmt.Errorf("consul: role name required")
	}
	path := fmt.Sprintf("%s/roles/%s", s.mount, name)
	data, err := s.client.ReadSecret(path)
	if err != nil {
		return nil, fmt.Errorf("consul: get role %q: %w", name, err)
	}
	leaseTTL, _ := data["lease"].(string)
	d, _ := time.ParseDuration(leaseTTL)
	tokenType, _ := data["token_type"].(string)
	var policies []string
	if ps, ok := data["policies"].([]interface{}); ok {
		for _, p := range ps {
			if s, ok := p.(string); ok {
				policies = append(policies, s)
			}
		}
	}
	return &ConsulRole{
		Name:      name,
		Lease:     d,
		TokenType: tokenType,
		Policies:  policies,
	}, nil
}
