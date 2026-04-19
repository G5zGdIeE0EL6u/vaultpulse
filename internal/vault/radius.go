package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// RADIUSUser represents a RADIUS auth backend user entry.
type RADIUSUser struct {
	Username  string
	Policies  []string
	CreatedAt time.Time
}

// RADIUSScanner reads users from a Vault RADIUS auth mount.
type RADIUSScanner struct {
	client *Client
	mount  string
}

// NewRADIUSScanner returns a new RADIUSScanner. Returns an error if client is nil.
func NewRADIUSScanner(client *Client, mount string) (*RADIUSScanner, error) {
	if client == nil {
		return nil, fmt.Errorf("radius: client must not be nil")
	}
	if mount == "" {
		mount = "radius"
	}
	return &RADIUSScanner{client: client, mount: mount}, nil
}

// ListUsers returns all usernames registered under the RADIUS mount.
func (s *RADIUSScanner) ListUsers() ([]string, error) {
	path := fmt.Sprintf("/v1/auth/%s/users", s.mount)
	resp, err := s.client.RawRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("radius: list users: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("radius: list users: unexpected status %d", resp.StatusCode)
	}
	var result struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("radius: list users: decode: %w", err)
	}
	return result.Data.Keys, nil
}

// GetUser returns details for a specific RADIUS user.
func (s *RADIUSScanner) GetUser(username string) (*RADIUSUser, error) {
	if username == "" {
		return nil, fmt.Errorf("radius: username must not be empty")
	}
	path := fmt.Sprintf("/v1/auth/%s/users/%s", s.mount, username)
	resp, err := s.client.RawRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("radius: get user: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("radius: get user: unexpected status %d", resp.StatusCode)
	}
	var result struct {
		Data struct {
			Policies []string `json:"policies"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("radius: get user: decode: %w", err)
	}
	return &RADIUSUser{
		Username: username,
		Policies: result.Data.Policies,
	}, nil
}
