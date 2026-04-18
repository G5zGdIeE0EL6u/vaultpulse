package vault

import (
	"errors"
	"fmt"
	"time"
)

// LDAPRole represents an LDAP auth role/group configuration.
type LDAPRole struct {
	Name      string
	Policies  []string
	TTL       time.Duration
	MaxTTL    time.Duration
	CreatedAt time.Time
}

// IsExpired returns true if the role's TTL has elapsed since creation.
func (r *LDAPRole) IsExpired() bool {
	if r.TTL == 0 {
		return false
	}
	return time.Since(r.CreatedAt) > r.TTL
}

// TimeUntilExpiry returns the duration until the role expires.
func (r *LDAPRole) TimeUntilExpiry() time.Duration {
	if r.TTL == 0 {
		return 0
	}
	return r.TTL - time.Since(r.CreatedAt)
}

// LDAPScanner scans LDAP auth roles from Vault.
type LDAPScanner struct {
	client *Client
	mount  string
}

// NewLDAPScanner creates a new LDAPScanner.
func NewLDAPScanner(c *Client, mount string) (*LDAPScanner, error) {
	if c == nil {
		return nil, errors.New("vault client is required")
	}
	if mount == "" {
		mount = "ldap"
	}
	return &LDAPScanner{client: c, mount: mount}, nil
}

// ListRoles returns all LDAP group names configured under the mount.
func (s *LDAPScanner) ListRoles() ([]string, error) {
	path := fmt.Sprintf("/v1/auth/%s/groups", s.mount)
	resp, err := s.client.RawList(path)
	if err != nil {
		return nil, fmt.Errorf("ldap list roles: %w", err)
	}
	keys, _ := resp["keys"].([]interface{})
	var names []string
	for _, k := range keys {
		if name, ok := k.(string); ok {
			names = append(names, name)
		}
	}
	return names, nil
}

// GetRole fetches details for a single LDAP group role.
func (s *LDAPScanner) GetRole(name string) (*LDAPRole, error) {
	if name == "" {
		return nil, errors.New("role name is required")
	}
	path := fmt.Sprintf("/v1/auth/%s/groups/%s", s.mount, name)
	data, err := s.client.RawRead(path)
	if err != nil {
		return nil, fmt.Errorf("ldap get role %q: %w", name, err)
	}
	role := &LDAPRole{Name: name, CreatedAt: time.Now()}
	if ttlRaw, ok := data["ttl"]; ok {
		if ttlSec, ok := ttlRaw.(float64); ok {
			role.TTL = time.Duration(ttlSec) * time.Second
		}
	}
	if maxTTLRaw, ok := data["max_ttl"]; ok {
		if maxTTLSec, ok := maxTTLRaw.(float64); ok {
			role.MaxTTL = time.Duration(maxTTLSec) * time.Second
		}
	}
	return role, nil
}
