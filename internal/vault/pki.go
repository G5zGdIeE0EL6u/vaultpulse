package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// PKIRole represents a PKI secrets engine role.
type PKIRole struct {
	Name    string
	MaxTTL  time.Duration
	TTL     time.Duration
	AllowedDomains []string
}

// PKIScanner scans PKI secrets engine roles.
type PKIScanner struct {
	client *Client
	mount  string
}

// NewPKIScanner creates a new PKIScanner. Returns nil if client is nil.
func NewPKIScanner(client *Client, mount string) *PKIScanner {
	if client == nil {
		return nil
	}
	if mount == "" {
		mount = "pki"
	}
	return &PKIScanner{client: client, mount: mount}
}

// ListRoles returns all PKI role names under the configured mount.
func (s *PKIScanner) ListRoles() ([]string, error) {
	path := fmt.Sprintf("/v1/%s/roles?list=true", s.mount)
	resp, err := s.client.RawRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pki list roles: status %d", resp.StatusCode)
	}
	var out struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Data.Keys, nil
}

// GetRole fetches details for a single PKI role.
func (s *PKIScanner) GetRole(name string) (*PKIRole, error) {
	if name == "" {
		return nil, fmt.Errorf("role name must not be empty")
	}
	path := fmt.Sprintf("/v1/%s/roles/%s", s.mount, name)
	resp, err := s.client.RawRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pki get role %q: status %d", name, resp.StatusCode)
	}
	var out struct {
		Data struct {
			MaxTTL         string   `json:"max_ttl"`
			TTL            string   `json:"ttl"`
			AllowedDomains []string `json:"allowed_domains"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	maxTTL, _ := time.ParseDuration(out.Data.MaxTTL)
	ttl, _ := time.ParseDuration(out.Data.TTL)
	return &PKIRole{
		Name:           name,
		MaxTTL:         maxTTL,
		TTL:            ttl,
		AllowedDomains: out.Data.AllowedDomains,
	}, nil
}
