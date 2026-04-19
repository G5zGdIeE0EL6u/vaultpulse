package vault

import (
	"fmt"
	"time"
)

// RabbitMQRole represents a RabbitMQ secret engine role.
type RabbitMQRole struct {
	Name      string
	Vhosts    string
	Tags      string
	TTL       time.Duration
	MaxTTL    time.Duration
	CreatedAt time.Time
}

// IsExpired returns true if the role's TTL has elapsed.
func (r *RabbitMQRole) IsExpired() bool {
	if r.TTL <= 0 {
		return false
	}
	return time.Since(r.CreatedAt) >= r.TTL
}

// TimeUntilExpiry returns the duration remaining before expiry.
func (r *RabbitMQRole) TimeUntilExpiry() time.Duration {
	if r.TTL <= 0 {
		return 0
	}
	return r.TTL - time.Since(r.CreatedAt)
}

// RabbitMQScanner scans RabbitMQ secret engine roles.
type RabbitMQScanner struct {
	client *Client
	mount  string
}

// NewRabbitMQScanner creates a new RabbitMQScanner.
func NewRabbitMQScanner(client *Client, mount string) (*RabbitMQScanner, error) {
	if client == nil {
		return nil, fmt.Errorf("client must not be nil")
	}
	if mount == "" {
		mount = "rabbitmq"
	}
	return &RabbitMQScanner{client: client, mount: mount}, nil
}

// ListRoles returns all role names under the RabbitMQ mount.
func (s *RabbitMQScanner) ListRoles() ([]string, error) {
	path := fmt.Sprintf("%s/roles", s.mount)
	secret, err := s.client.vault.Logical().List(path)
	if err != nil {
		return nil, fmt.Errorf("list rabbitmq roles: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}
	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return []string{}, nil
	}
	names := make([]string, 0, len(keys))
	for _, k := range keys {
		if name, ok := k.(string); ok {
			names = append(names, name)
		}
	}
	return names, nil
}

// GetRole fetches details for a single RabbitMQ role.
func (s *RabbitMQScanner) GetRole(name string) (*RabbitMQRole, error) {
	if name == "" {
		return nil, fmt.Errorf("role name must not be empty")
	}
	path := fmt.Sprintf("%s/roles/%s", s.mount, name)
	secret, err := s.client.vault.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("read rabbitmq role %s: %w", name, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("role %s not found", name)
	}
	role := &RabbitMQRole{
		Name:      name,
		CreatedAt: time.Now(),
	}
	if v, ok := secret.Data["vhosts"].(string); ok {
		role.Vhosts = v
	}
	if v, ok := secret.Data["tags"].(string); ok {
		role.Tags = v
	}
	if v, ok := secret.Data["ttl"].(json.Number); ok {
		if n, err := v.Int64(); err == nil {
			role.TTL = time.Duration(n) * time.Second
		}
	}
	if v, ok := secret.Data["max_ttl"].(json.Number); ok {
		if n, err := v.Int64(); err == nil {
			role.MaxTTL = time.Duration(n) * time.Second
		}
	}
	return role, nil
}
