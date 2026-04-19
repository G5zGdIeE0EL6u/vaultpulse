package vault

import (
	"encoding/json"
	"fmt"
	"time"
)

// GCPRoleInfo holds metadata about a GCP secrets engine role.
type GCPRoleInfo struct {
	Name           string
	SecretType     string
	TokenTTL       time.Duration
	TokenMaxTTL    time.Duration
	ServiceAccounts []string
}

// IsExpired returns true if the role's max TTL has elapsed.
func (g *GCPRoleInfo) IsExpired() bool {
	return g.TokenMaxTTL > 0 && time.Now().After(time.Now().Add(g.TokenMaxTTL))
}

// TimeUntilExpiry returns the duration until the token max TTL expires.
func (g *GCPRoleInfo) TimeUntilExpiry() time.Duration {
	return g.TokenMaxTTL
}

// GCPScanner scans GCP secrets engine roles from Vault.
type GCPScanner struct {
	client *Client
	mount  string
}

// NewGCPScanner creates a new GCPScanner. Returns an error if client is nil.
func NewGCPScanner(client *Client, mount string) (*GCPScanner, error) {
	if client == nil {
		return nil, fmt.Errorf("vault client must not be nil")
	}
	if mount == "" {
		mount = "gcp"
	}
	return &GCPScanner{client: client, mount: mount}, nil
}

// ListRoles returns all GCP role names under the configured mount.
func (s *GCPScanner) ListRoles() ([]string, error) {
	path := fmt.Sprintf("%s/roles", s.mount)
	data, err := s.client.ReadSecret(path)
	if err != nil {
		return nil, fmt.Errorf("list gcp roles: %w", err)
	}
	keys, ok := data["keys"].([]interface{})
	if !ok {
		return []string{}, nil
	}
	var roles []string
	for _, k := range keys {
		if name, ok := k.(string); ok {
			roles = append(roles, name)
		}
	}
	return roles, nil
}

// GetRole fetches details for a single GCP role by name.
func (s *GCPScanner) GetRole(name string) (*GCPRoleInfo, error) {
	if name == "" {
		return nil, fmt.Errorf("role name must not be empty")
	}
	path := fmt.Sprintf("%s/roles/%s", s.mount, name)
	data, err := s.client.ReadSecret(path)
	if err != nil {
		return nil, fmt.Errorf("get gcp role %q: %w", name, err)
	}
	b, _ := json.Marshal(data)
	var raw struct {
		SecretType      string   `json:"secret_type"`
		TokenTTL        int64    `json:"token_ttl"`
		TokenMaxTTL     int64    `json:"token_max_ttl"`
		ServiceAccounts []string `json:"bindings"`
	}
	_ = json.Unmarshal(b, &raw)
	return &GCPRoleInfo{
		Name:            name,
		SecretType:      raw.SecretType,
		TokenTTL:        time.Duration(raw.TokenTTL) * time.Second,
		TokenMaxTTL:     time.Duration(raw.TokenMaxTTL) * time.Second,
		ServiceAccounts: raw.ServiceAccounts,
	}, nil
}
