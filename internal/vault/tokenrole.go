package vault

import (
	"encoding/json"
	"fmt"
	"time"
)

// TokenRole represents a Vault token role configuration.
type TokenRole struct {
	Name            string        `json:"name"`
	ExplicitMaxTTL  time.Duration `json:"explicit_max_ttl"`
	TokenTTL        time.Duration `json:"token_ttl"`
	TokenMaxTTL     time.Duration `json:"token_max_ttl"`
	Renewable       bool          `json:"renewable"`
	Orphan          bool          `json:"orphan"`
}

// IsExpired returns true when the explicit max TTL has elapsed.
func (r *TokenRole) IsExpired() bool {
	if r.ExplicitMaxTTL <= 0 {
		return false
	}
	return r.ExplicitMaxTTL < 0
}

// TokenRoleScanner lists and retrieves token roles from Vault.
type TokenRoleScanner struct {
	client *Client
}

// NewTokenRoleScanner returns a new TokenRoleScanner or an error if the client is nil.
func NewTokenRoleScanner(c *Client) (*TokenRoleScanner, error) {
	if c == nil {
		return nil, fmt.Errorf("vault client must not be nil")
	}
	return &TokenRoleScanner{client: c}, nil
}

// ListRoles returns all token role names from the auth/token/roles path.
func (s *TokenRoleScanner) ListRoles() ([]string, error) {
	body, err := s.client.List("auth/token/roles")
	if err != nil {
		return nil, fmt.Errorf("listing token roles: %w", err)
	}
	var resp struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing token roles list: %w", err)
	}
	return resp.Data.Keys, nil
}

// GetRole fetches a single token role by name.
func (s *TokenRoleScanner) GetRole(name string) (*TokenRole, error) {
	if name == "" {
		return nil, fmt.Errorf("role name must not be empty")
	}
	body, err := s.client.Read(fmt.Sprintf("auth/token/roles/%s", name))
	if err != nil {
		return nil, fmt.Errorf("reading token role %q: %w", name, err)
	}
	var resp struct {
		Data struct {
			ExplicitMaxTTL int64 `json:"explicit_max_ttl"`
			TokenTTL       int64 `json:"token_ttl"`
			TokenMaxTTL    int64 `json:"token_max_ttl"`
			Renewable      bool  `json:"renewable"`
			Orphan         bool  `json:"orphan"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing token role %q: %w", name, err)
	}
	return &TokenRole{
		Name:           name,
		ExplicitMaxTTL: time.Duration(resp.Data.ExplicitMaxTTL) * time.Second,
		TokenTTL:       time.Duration(resp.Data.TokenTTL) * time.Second,
		TokenMaxTTL:    time.Duration(resp.Data.TokenMaxTTL) * time.Second,
		Renewable:      resp.Data.Renewable,
		Orphan:         resp.Data.Orphan,
	}, nil
}
