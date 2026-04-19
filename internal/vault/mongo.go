package vault

import (
	"fmt"
	"time"
)

// MongoRole represents a MongoDB database role configuration in Vault.
type MongoRole struct {
	Name              string
	DefaultTTL        time.Duration
	MaxTTL            time.Duration
	CreationStatements []string
}

// IsExpired returns true if the role's MaxTTL has elapsed.
func (r *MongoRole) IsExpired() bool {
	if r.MaxTTL <= 0 {
		return false
	}
	return time.Now().After(time.Now().Add(r.MaxTTL))
}

// MongoScanner scans MongoDB roles from Vault's database secrets engine.
type MongoScanner struct {
	client *Client
	mount  string
}

// NewMongoScanner creates a new MongoScanner. Returns an error if client is nil.
func NewMongoScanner(client *Client, mount string) (*MongoScanner, error) {
	if client == nil {
		return nil, fmt.Errorf("mongo: client must not be nil")
	}
	if mount == "" {
		mount = "database"
	}
	return &MongoScanner{client: client, mount: mount}, nil
}

// ListRoles returns all MongoDB role names under the configured mount.
func (s *MongoScanner) ListRoles() ([]string, error) {
	path := fmt.Sprintf("%s/roles", s.mount)
	secret, err := s.client.vault.Logical().List(path)
	if err != nil {
		return nil, fmt.Errorf("mongo: list roles: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, nil
	}
	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return nil, nil
	}
	var roles []string
	for _, k := range keys {
		if s, ok := k.(string); ok {
			roles = append(roles, s)
		}
	}
	return roles, nil
}

// GetRole fetches details for a single MongoDB role by name.
func (s *MongoScanner) GetRole(name string) (*MongoRole, error) {
	if name == "" {
		return nil, fmt.Errorf("mongo: role name must not be empty")
	}
	path := fmt.Sprintf("%s/roles/%s", s.mount, name)
	secret, err := s.client.vault.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("mongo: get role %q: %w", name, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("mongo: role %q not found", name)
	}
	role := &MongoRole{Name: name}
	if v, ok := secret.Data["default_ttl"].(float64); ok {
		role.DefaultTTL = time.Duration(v) * time.Second
	}
	if v, ok := secret.Data["max_ttl"].(float64); ok {
		role.MaxTTL = time.Duration(v) * time.Second
	}
	return role, nil
}
