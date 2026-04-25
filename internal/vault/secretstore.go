package vault

import (
	"encoding/json"
	"fmt"
	"time"
)

// SecretStoreEntry represents a tracked secret with metadata.
type SecretStoreEntry struct {
	Path      string            `json:"path"`
	Mount     string            `json:"mount"`
	Version   int               `json:"version"`
	CreatedAt time.Time         `json:"created_at"`
	ExpiresAt time.Time         `json:"expires_at"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// IsExpired returns true if the entry's expiry has passed.
func (e *SecretStoreEntry) IsExpired() bool {
	if e.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(e.ExpiresAt)
}

// TTL returns the remaining duration until expiry.
func (e *SecretStoreEntry) TTL() time.Duration {
	if e.ExpiresAt.IsZero() {
		return 0
	}
	return time.Until(e.ExpiresAt)
}

// SecretStoreScanner scans a Vault KV mount for secret entries.
type SecretStoreScanner struct {
	client *Client
	mount  string
}

// NewSecretStoreScanner creates a new SecretStoreScanner.
func NewSecretStoreScanner(client *Client, mount string) *SecretStoreScanner {
	if mount == "" {
		mount = "secret"
	}
	return &SecretStoreScanner{client: client, mount: mount}
}

// ListEntries returns all secret entries under the given prefix.
func (s *SecretStoreScanner) ListEntries(prefix string) ([]*SecretStoreEntry, error) {
	path := fmt.Sprintf("%s/metadata/%s", s.mount, prefix)
	resp, err := s.client.RawList(path)
	if err != nil {
		return nil, fmt.Errorf("secretstore: list %q: %w", path, err)
	}
	defer resp.Body.Close()

	var result struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("secretstore: decode list: %w", err)
	}

	entries := make([]*SecretStoreEntry, 0, len(result.Data.Keys))
	for _, key := range result.Data.Keys {
		entries = append(entries, &SecretStoreEntry{
			Path:  fmt.Sprintf("%s/%s", prefix, key),
			Mount: s.mount,
		})
	}
	return entries, nil
}
