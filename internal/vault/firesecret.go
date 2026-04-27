package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// FireSecretEntry represents a secret with a fire-and-forget TTL from a generic KV path.
type FireSecretEntry struct {
	Path      string
	Key       string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// IsExpired returns true if the secret's expiry has passed.
func (f *FireSecretEntry) IsExpired() bool {
	if f.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(f.ExpiresAt)
}

// TimeUntilExpiry returns the duration remaining before expiry.
func (f *FireSecretEntry) TimeUntilExpiry() time.Duration {
	if f.ExpiresAt.IsZero() {
		return 0
	}
	return time.Until(f.ExpiresAt)
}

// FireSecretScanner scans a KV mount for secrets with embedded expiry metadata.
type FireSecretScanner struct {
	client *Client
	mount  string
}

// NewFireSecretScanner creates a new FireSecretScanner.
// Returns an error if client is nil.
func NewFireSecretScanner(client *Client, mount string) (*FireSecretScanner, error) {
	if client == nil {
		return nil, fmt.Errorf("vault client must not be nil")
	}
	if mount == "" {
		mount = "secret"
	}
	return &FireSecretScanner{client: client, mount: mount}, nil
}

// ListPaths returns all secret paths under the mount.
func (s *FireSecretScanner) ListPaths() ([]string, error) {
	url := fmt.Sprintf("%s/v1/%s/metadata?list=true", s.client.Address, s.mount)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", s.client.Token)
	resp, err := s.client.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	var body struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	return body.Data.Keys, nil
}
