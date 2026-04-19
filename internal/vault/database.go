package vault

import (
	"encoding/json"
	"fmt"
	"time"
)

// DatabaseRole represents a dynamic database role with its TTL configuration.
type DatabaseRole struct {
	Name           string
	Mount          string
	DefaultTTL     time.Duration
	MaxTTL         time.Duration
	CreationStmts  []string
}

// IsExpired returns true if the max TTL has elapsed.
func (r *DatabaseRole) IsExpired() bool {
	return r.MaxTTL > 0 && time.Now().After(time.Now().Add(-r.MaxTTL))
}

// DatabaseScanner scans Vault database secret engine roles.
type DatabaseScanner struct {
	client *Client
	mount  string
}

// NewDatabaseScanner creates a new DatabaseScanner.
func NewDatabaseScanner(client *Client, mount string) (*DatabaseScanner, error) {
	if client == nil {
		return nil, fmt.Errorf("vault client must not be nil")
	}
	if mount == "" {
		mount = "database"
	}
	return &DatabaseScanner{client: client, mount: mount}, nil
}

// ListRoles returns all role names under the database mount.
func (s *DatabaseScanner) ListRoles() ([]string, error) {
	path := fmt.Sprintf("/v1/%s/roles", s.mount)
	resp, err := s.client.httpClient.Get(s.client.address + path + "?list=true")
	if err != nil {
		return nil, fmt.Errorf("list roles request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	var result struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode error: %w", err)
	}
	return result.Data.Keys, nil
}

// GetRole retrieves details for a specific database role.
func (s *DatabaseScanner) GetRole(name string) (*DatabaseRole, error) {
	if name == "" {
		return nil, fmt.Errorf("role name must not be empty")
	}
	path := fmt.Sprintf("/v1/%s/roles/%s", s.mount, name)
	resp, err := s.client.httpClient.Get(s.client.address + path)
	if err != nil {
		return nil, fmt.Errorf("get role request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("role %q not found", name)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	var result struct {
		Data struct {
			DefaultTTL int      `json:"default_ttl"`
			MaxTTL     int      `json:"max_ttl"`
			Stmts      []string `json:"creation_statements"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode error: %w", err)
	}
	return &DatabaseRole{
		Name:          name,
		Mount:         s.mount,
		DefaultTTL:    time.Duration(result.Data.DefaultTTL) * time.Second,
		MaxTTL:        time.Duration(result.Data.MaxTTL) * time.Second,
		CreationStmts: result.Data.Stmts,
	}, nil
}
