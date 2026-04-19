package vault

import (
	"encoding/json"
	"fmt"
	"time"
)

// NomadRole represents a Vault Nomad secret engine role.
type NomadRole struct {
	Name      string
	Policies  []string
	LeaseTTL  time.Duration
	MaxTTL    time.Duration
	Global    bool
	Type      string
}

// IsExpired returns true if the role has no TTL configured.
func (r *NomadRole) IsExpired() bool {
	return r.LeaseTTL == 0
}

// TimeUntilExpiry returns the lease TTL duration.
func (r *NomadRole) TimeUntilExpiry() time.Duration {
	return r.LeaseTTL
}

// NomadScanner scans Vault's Nomad secret engine roles.
type NomadScanner struct {
	client *Client
	mount  string
}

// NewNomadScanner creates a new NomadScanner.
func NewNomadScanner(client *Client, mount string) *NomadScanner {
	if client == nil {
		return nil
	}
	if mount == "" {
		mount = "nomad"
	}
	return &NomadScanner{client: client, mount: mount}
}

// ListRoles returns all role names from the Nomad secret engine.
func (s *NomadScanner) ListRoles() ([]string, error) {
	path := fmt.Sprintf("/v1/%s/role", s.mount)
	resp, err := s.client.RawRequest("LIST", path, nil)
	if err != nil {
		return nil, fmt.Errorf("nomad: list roles: %w", err)
	}
	defer resp.Body.Close()
	var result struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("nomad: decode roles: %w", err)
	}
	return result.Data.Keys, nil
}

// GetRole retrieves a specific Nomad role by name.
func (s *NomadScanner) GetRole(name string) (*NomadRole, error) {
	if name == "" {
		return nil, fmt.Errorf("nomad: role name required")
	}
	path := fmt.Sprintf("/v1/%s/role/%s", s.mount, name)
	resp, err := s.client.RawRequest("GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("nomad: get role %s: %w", name, err)
	}
	defer resp.Body.Close()
	var result struct {
		Data struct {
			Policies []string `json:"policies"`
			LeaseTTL int      `json:"lease"`
			MaxTTL   int      `json:"max_ttl"`
			Global   bool     `json:"global"`
			Type     string   `json:"type"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("nomad: decode role %s: %w", name, err)
	}
	return &NomadRole{
		Name:     name,
		Policies: result.Data.Policies,
		LeaseTTL: time.Duration(result.Data.LeaseTTL) * time.Second,
		MaxTTL:   time.Duration(result.Data.MaxTTL) * time.Second,
		Global:   result.Data.Global,
		Type:     result.Data.Type,
	}, nil
}
