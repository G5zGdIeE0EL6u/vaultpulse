package vault

import (
	"encoding/json"
	"fmt"
	"time"
)

// AzureRole represents an Azure secrets engine role.
type AzureRole struct {
	Name           string
	ApplicationObjectID string
	TTL            time.Duration
	MaxTTL         time.Duration
}

// IsExpired returns true if the role TTL has elapsed.
func (r *AzureRole) IsExpired() bool {
	return r.TTL <= 0
}

// TimeUntilExpiry returns the duration until the role expires.
func (r *AzureRole) TimeUntilExpiry() time.Duration {
	return r.TTL
}

// AzureScanner scans Azure secret engine roles.
type AzureScanner struct {
	client *Client
	mount  string
}

// NewAzureScanner creates a new AzureScanner. Defaults mount to "azure".
func NewAzureScanner(client *Client, mount string) *AzureScanner {
	if mount == "" {
		mount = "azure"
	}
	return &AzureScanner{client: client, mount: mount}
}

// ListRoles returns all role names under the Azure mount.
func (s *AzureScanner) ListRoles() ([]string, error) {
	if s.client == nil {
		return nil, fmt.Errorf("azure: nil client")
	}
	path := fmt.Sprintf("/v1/%s/roles", s.mount)
	resp, err := s.client.RawRequest("LIST", path, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: list roles: %w", err)
	}
	defer resp.Body.Close()
	var result struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("azure: decode roles: %w", err)
	}
	return result.Data.Keys, nil
}

// GetRole fetches details for a single Azure role.
func (s *AzureScanner) GetRole(name string) (*AzureRole, error) {
	if name == "" {
		return nil, fmt.Errorf("azure: role name required")
	}
	path := fmt.Sprintf("/v1/%s/roles/%s", s.mount, name)
	resp, err := s.client.RawRequest("GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: get role %s: %w", name, err)
	}
	defer resp.Body.Close()
	var result struct {
		Data struct {
			ApplicationObjectID string `json:"application_object_id"`
			TTL                 string `json:"ttl"`
			MaxTTL              string `json:"max_ttl"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("azure: decode role %s: %w", name, err)
	}
	ttl, _ := time.ParseDuration(result.Data.TTL)
	maxTTL, _ := time.ParseDuration(result.Data.MaxTTL)
	return &AzureRole{
		Name:                name,
		ApplicationObjectID: result.Data.ApplicationObjectID,
		TTL:                 ttl,
		MaxTTL:              maxTTL,
	}, nil
}
