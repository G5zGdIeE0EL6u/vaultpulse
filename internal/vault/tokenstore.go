package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// TokenStoreEntry represents a token accessor entry in Vault's token store.
type TokenStoreEntry struct {
	Accessor    string    `json:"accessor"`
	CreationTime int64    `json:"creation_time"`
	TTL         int64     `json:"ttl"`
	DisplayName string    `json:"display_name"`
	Policies    []string  `json:"policies"`
	ExpireTime  time.Time `json:"expire_time"`
}

// IsExpired returns true if the token store entry has expired.
func (t *TokenStoreEntry) IsExpired() bool {
	if t.TTL <= 0 {
		return false
	}
	return time.Now().After(t.ExpireTime)
}

// TimeUntilExpiry returns the duration until the entry expires.
func (t *TokenStoreEntry) TimeUntilExpiry() time.Duration {
	if t.TTL <= 0 {
		return 0
	}
	return time.Until(t.ExpireTime)
}

// TokenStoreScanner lists and inspects token accessors from Vault.
type TokenStoreScanner struct {
	client *Client
}

// NewTokenStoreScanner returns a new TokenStoreScanner or an error if client is nil.
func NewTokenStoreScanner(client *Client) (*TokenStoreScanner, error) {
	if client == nil {
		return nil, fmt.Errorf("tokenstore: client must not be nil")
	}
	return &TokenStoreScanner{client: client}, nil
}

// ListAccessors returns all token accessors from the token store.
func (s *TokenStoreScanner) ListAccessors() ([]string, error) {
	req, err := http.NewRequest(http.MethodList, s.client.address+"/v1/auth/token/accessors", nil)
	if err != nil {
		return nil, fmt.Errorf("tokenstore: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", s.client.token)
	resp, err := s.client.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tokenstore: list accessors: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tokenstore: unexpected status %d", resp.StatusCode)
	}
	var body struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("tokenstore: decode response: %w", err)
	}
	return body.Data.Keys, nil
}

// LookupAccessor retrieves details for a specific token accessor.
func (s *TokenStoreScanner) LookupAccessor(accessor string) (*TokenStoreEntry, error) {
	if accessor == "" {
		return nil, fmt.Errorf("tokenstore: accessor must not be empty")
	}
	payload := fmt.Sprintf(`{"accessor":%q}`, accessor)
	req, err := http.NewRequest(http.MethodPost,
		s.client.address+"/v1/auth/token/lookup-accessor",
		stringsReader(payload))
	if err != nil {
		return nil, fmt.Errorf("tokenstore: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", s.client.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tokenstore: lookup accessor: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tokenstore: unexpected status %d", resp.StatusCode)
	}
	var body struct {
		Data TokenStoreEntry `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("tokenstore: decode response: %w", err)
	}
	entry := body.Data
	if entry.TTL > 0 {
		entry.ExpireTime = time.Unix(entry.CreationTime, 0).Add(time.Duration(entry.TTL) * time.Second)
	}
	return &entry, nil
}
