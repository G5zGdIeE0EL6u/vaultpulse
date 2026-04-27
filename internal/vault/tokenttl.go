package vault

import (
	"fmt"
	"time"
)

// TokenTTLEntry represents a token with its TTL metadata.
type TokenTTLEntry struct {
	Accessor  string
	DisplayName string
	TTL       time.Duration
	CreatedAt time.Time
	Policies  []string
}

// IsExpired returns true if the token TTL has elapsed.
func (t *TokenTTLEntry) IsExpired() bool {
	return t.TTL <= 0
}

// TimeUntilExpiry returns the remaining duration before expiry.
func (t *TokenTTLEntry) TimeUntilExpiry() time.Duration {
	if t.IsExpired() {
		return 0
	}
	return t.TTL
}

// TokenTTLScanner scans active tokens and reports their TTL status.
type TokenTTLScanner struct {
	client *Client
	mount  string
}

// NewTokenTTLScanner creates a new TokenTTLScanner.
// Returns nil if client is nil.
func NewTokenTTLScanner(client *Client, mount string) *TokenTTLScanner {
	if client == nil {
		return nil
	}
	if mount == "" {
		mount = "auth/token"
	}
	return &TokenTTLScanner{client: client, mount: mount}
}

// ListAccessors returns all token accessors from Vault.
func (s *TokenTTLScanner) ListAccessors() ([]string, error) {
	path := fmt.Sprintf("/v1/%s/accessors", s.mount)
	data, err := s.client.List(path)
	if err != nil {
		return nil, fmt.Errorf("list accessors: %w", err)
	}
	keys, _ := data["keys"].([]interface{})
	accessors := make([]string, 0, len(keys))
	for _, k := range keys {
		if acc, ok := k.(string); ok {
			accessors = append(accessors, acc)
		}
	}
	return accessors, nil
}

// LookupAccessor retrieves TTL info for a single accessor.
func (s *TokenTTLScanner) LookupAccessor(accessor string) (*TokenTTLEntry, error) {
	if accessor == "" {
		return nil, fmt.Errorf("accessor must not be empty")
	}
	path := fmt.Sprintf("/v1/%s/lookup-accessor", s.mount)
	data, err := s.client.Write(path, map[string]interface{}{"accessor": accessor})
	if err != nil {
		return nil, fmt.Errorf("lookup accessor %s: %w", accessor, err)
	}
	ttlSec, _ := data["ttl"].(float64)
	displayName, _ := data["display_name"].(string)
	policiesRaw, _ := data["policies"].([]interface{})
	policies := make([]string, 0, len(policiesRaw))
	for _, p := range policiesRaw {
		if ps, ok := p.(string); ok {
			policies = append(policies, ps)
		}
	}
	return &TokenTTLEntry{
		Accessor:    accessor,
		DisplayName: displayName,
		TTL:         time.Duration(ttlSec) * time.Second,
		CreatedAt:   time.Now(),
		Policies:    policies,
	}, nil
}
