package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// SSHRole represents a Vault SSH secret engine role.
type SSHRole struct {
	Name       string
	KeyType    string
	TTL        time.Duration
	MaxTTL     time.Duration
	AllowedUsers string
}

// SSHScanner lists and inspects SSH roles from a Vault SSH secrets engine.
type SSHScanner struct {
	client *Client
	mount  string
}

// NewSSHScanner creates a new SSHScanner. Returns an error if client is nil.
func NewSSHScanner(client *Client, mount string) (*SSHScanner, error) {
	if client == nil {
		return nil, fmt.Errorf("ssh: client must not be nil")
	}
	if mount == "" {
		mount = "ssh"
	}
	return &SSHScanner{client: client, mount: mount}, nil
}

// ListRoles returns all SSH role names under the configured mount.
func (s *SSHScanner) ListRoles() ([]string, error) {
	path := fmt.Sprintf("/v1/%s/roles?list=true", s.mount)
	resp, err := s.client.Do(http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("ssh: list roles: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil,: list roles: status %d", resp.StatusCode)
	}
	var body struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("ssh: decode roles: %w", err)
	}
	return body.Data.Keys, nil
}

// GetRole fetches details for a named SSH role.
func (s *SSHScanner) GetRole(name string) (*SSHRole, error) {
	if name == "" {
		return nil, fmt.Errorf("ssh: role name must not be empty")
	}
	path := fmt.Sprintf("/v1/%s/roles/%s", s.mount, name)
	resp, err := s.client.Do(http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("ssh: get role %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("ssh: role %q not found", name)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ssh: get role %s: status %d", name, resp.StatusCode)
	}
	var body struct {
		Data struct {
			KeyType      string `json:"key_type"`
			TTL          string `json:"ttl"`
			MaxTTL       string `json:"max_ttl"`
			AllowedUsers string `json:"allowed_users"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("ssh: decode role: %w", err)
	}
	ttl, _ := time.ParseDuration(body.Data.TTL)
	maxTTL, _ := time.ParseDuration(body.Data.MaxTTL)
	return &SSHRole{
		Name:         name,
		KeyType:      body.Data.KeyType,
		TTL:          ttl,
		MaxTTL:       maxTTL,
		AllowedUsers: body.Data.AllowedUsers,
	}, nil
}
