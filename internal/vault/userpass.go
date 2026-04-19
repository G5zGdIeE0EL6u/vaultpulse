package vault

import (
	"errors"
	"fmt"
	"time"
)

// UserpassRole represents a Vault userpass auth role entry.
type UserpassRole struct {
	Username      string
	TokenTTL      time.Duration
	TokenMaxTTL   time.Duration
	TokenPolicies []string
}

// IsExpired returns true if the token max TTL has elapsed.
func (u *UserpassRole) IsExpired() bool {
	return u.TokenMaxTTL > 0 && time.Now().After(time.Now().Add(u.TokenMaxTTL))
}

// TimeUntilExpiry returns the duration until the token max TTL expires.
func (u *UserpassRole) TimeUntilExpiry() time.Duration {
	if u.TokenMaxTTL <= 0 {
		return 0
	}
	return u.TokenMaxTTL
}

// UserpassScanner scans Vault userpass auth users.
type UserpassScanner struct {
	client *Client
	mount  string
}

// NewUserpassScanner creates a new UserpassScanner.
func NewUserpassScanner(client *Client, mount string) (*UserpassScanner, error) {
	if client == nil {
		return nil, errors.New("userpass: client is nil")
	}
	if mount == "" {
		mount = "userpass"
	}
	return &UserpassScanner{client: client, mount: mount}, nil
}

// ListUsers returns all usernames registered under the mount.
func (s *UserpassScanner) ListUsers() ([]string, error) {
	path := fmt.Sprintf("auth/%s/users", s.mount)
	secret, err := s.client.vault.Logical().List(path)
	if err != nil {
		return nil, fmt.Errorf("userpass: list users: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}
	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return []string{}, nil
	}
	users := make([]string, 0, len(keys))
	for _, k := range keys {
		if s, ok := k.(string); ok {
			users = append(users, s)
		}
	}
	return users, nil
}

// GetUser retrieves details for a specific userpass user.
func (s *UserpassScanner) GetUser(username string) (*UserpassRole, error) {
	if username == "" {
		return nil, errors.New("userpass: username is empty")
	}
	path := fmt.Sprintf("auth/%s/users/%s", s.mount, username)
	secret, err := s.client.vault.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("userpass: get user %s: %w", username, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("userpass: user %s not found", username)
	}
	role := &UserpassRole{Username: username}
	if v, ok := secret.Data["token_ttl"].(float64); ok {
		role.TokenTTL = time.Duration(v) * time.Second
	}
	if v, ok := secret.Data["token_max_ttl"].(float64); ok {
		role.TokenMaxTTL = time.Duration(v) * time.Second
	}
	return role, nil
}
