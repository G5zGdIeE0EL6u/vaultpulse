package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// SSHCAInfo holds information about an SSH CA signing key.
type SSHCAInfo struct {
	Mount     string
	PublicKey string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// IsExpired returns true if the CA key has passed its expiry time.
func (s SSHCAInfo) IsExpired() bool {
	if s.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(s.ExpiresAt)
}

// TimeUntilExpiry returns the duration until the CA key expires.
func (s SSHCAInfo) TimeUntilExpiry() time.Duration {
	if s.ExpiresAt.IsZero() {
		return 0
	}
	return time.Until(s.ExpiresAt)
}

// SSHCAScanner scans SSH CA configurations in Vault.
type SSHCAScanner struct {
	client *Client
	mount  string
}

// NewSSHCAScanner creates a new SSHCAScanner.
func NewSSHCAScanner(client *Client, mount string) *SSHCAScanner {
	if client == nil {
		return nil
	}
	if mount == "" {
		mount = "ssh"
	}
	return &SSHCAScanner{client: client, mount: mount}
}

// GetCAInfo retrieves the public key and metadata for the SSH CA.
func (s *SSHCAScanner) GetCAInfo() (*SSHCAInfo, error) {
	path := fmt.Sprintf("/v1/%s/config/ca", s.mount)
	req, err := http.NewRequest(http.MethodGet, s.client.address+path, nil)
	if err != nil {
		return nil, fmt.Errorf("sshca: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", s.client.token)

	resp, err := s.client.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sshca: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("sshca: no CA configured on mount %q", s.mount)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sshca: unexpected status %d", resp.StatusCode)
	}

	var body struct {
		Data struct {
			PublicKey string `json:"public_key"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("sshca: decode response: %w", err)
	}

	return &SSHCAInfo{
		Mount:     s.mount,
		PublicKey: body.Data.PublicKey,
	}, nil
}
