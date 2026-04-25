package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// JWKSKey represents a single JSON Web Key from a JWKS endpoint.
type JWKSKey struct {
	KeyID     string    `json:"kid"`
	Algorithm string    `json:"alg"`
	KeyType   string    `json:"kty"`
	Use       string    `json:"use"`
	ExpiresAt time.Time `json:"-"`
}

// IsExpired returns true if the key's expiry time is in the past.
func (k JWKSKey) IsExpired() bool {
	if k.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(k.ExpiresAt)
}

// TimeUntilExpiry returns the duration until the key expires.
func (k JWKSKey) TimeUntilExpiry() time.Duration {
	if k.ExpiresAt.IsZero() {
		return 0
	}
	return time.Until(k.ExpiresAt)
}

// JWKSScanner scans Vault JWT/OIDC auth method JWKS endpoints.
type JWKSScanner struct {
	client *Client
}

// NewJWKSScanner creates a new JWKSScanner. Returns nil if client is nil.
func NewJWKSScanner(client *Client) *JWKSScanner {
	if client == nil {
		return nil
	}
	return &JWKSScanner{client: client}
}

// ListKeys retrieves the JWKS keys for the given JWT/OIDC mount path.
func (s *JWKSScanner) ListKeys(mount string) ([]JWKSKey, error) {
	if mount == "" {
		mount = "jwt"
	}
	path := fmt.Sprintf("/v1/auth/%s/.well-known/keys", mount)
	resp, err := s.client.RawGet(path)
	if err != nil {
		return nil, fmt.Errorf("jwks list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks list: unexpected status %d", resp.StatusCode)
	}
	var payload struct {
		Keys []JWKSKey `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("jwks list decode: %w", err)
	}
	return payload.Keys, nil
}
