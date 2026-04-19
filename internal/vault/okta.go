package vault

import (
	"fmt"
	"time"
)

// OktaUser represents a user configured in the Okta auth method.
type OktaUser struct {
	Username string
	Groups   []string
	Policies []string
	TTL      time.Duration
}

// IsExpired returns true if the TTL is zero or negative.
func (u *OktaUser) IsExpired() bool {
	return u.TTL <= 0
}

// OktaScanner scans Okta auth method users and groups.
type OktaScanner struct {
	client *Client
	mount  string
}

// NewOktaScanner creates a new OktaScanner. Returns nil if client is nil.
func NewOktaScanner(client *Client, mount string) *OktaScanner {
	if client == nil {
		return nil
	}
	if mount == "" {
		mount = "okta"
	}
	return &OktaScanner{client: client, mount: mount}
}

// ListUsers returns all users configured in the Okta auth mount.
func (s *OktaScanner) ListUsers() ([]string, error) {
	path := fmt.Sprintf("auth/%s/users", s.mount)
	secret, err := s.client.vault.Logical().List(path)
	if err != nil {
		return nil, fmt.Errorf("okta list users: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, nil
	}
	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return nil, nil
	}
	var users []string
	for _, k := range keys {
		if s, ok := k.(string); ok {
			users = append(users, s)
		}
	}
	return users, nil
}

// GetUser retrieves details for a specific Okta user.
func (s *OktaScanner) GetUser(username string) (*OktaUser, error) {
	if username == "" {
		return nil, fmt.Errorf("okta get user: username is required")
	}
	path := fmt.Sprintf("auth/%s/users/%s", s.mount, username)
	secret, err := s.client.vault.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("okta get user: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("okta get user: user %q not found", username)
	}
	user := &OktaUser{Username: username}
	if v, ok := secret.Data["policies"].([]interface{}); ok {
		for _, p := range v {
			if ps, ok := p.(string); ok {
				user.Policies = append(user.Policies, ps)
			}
		}
	}
	if v, ok := secret.Data["groups"].([]interface{}); ok {
		for _, g := range v {
			if gs, ok := g.(string); ok {
				user.Groups = append(user.Groups, gs)
			}
		}
	}
	if ttlRaw, ok := secret.Data["ttl"].(string); ok {
		if d, err := time.ParseDuration(ttlRaw); err == nil {
			user.TTL = d
		}
	}
	return user, nil
}
