package vault

import (
	"errors"
	"fmt"
	"time"
)

// LoginTokenRecord holds metadata about a Vault login token issued via auth methods.
type LoginTokenRecord struct {
	Accessor  string
	Path      string
	CreatedAt time.Time
	ExpiresAt time.Time
	Meta      map[string]string
}

// TTL returns the remaining duration until the token expires.
func (r *LoginTokenRecord) TTL() time.Duration {
	return time.Until(r.ExpiresAt)
}

// IsExpired reports whether the token has already expired.
func (r *LoginTokenRecord) IsExpired() bool {
	return r.ExpiresAt.Before(time.Now())
}

// LoginTokenScanner lists active login tokens via the Vault token accessor list.
type LoginTokenScanner struct {
	client *Client
}

// NewLoginTokenScanner creates a LoginTokenScanner. Returns an error if client is nil.
func NewLoginTokenScanner(c *Client) (*LoginTokenScanner, error) {
	if c == nil {
		return nil, errors.New("vault: client must not be nil")
	}
	return &LoginTokenScanner{client: c}, nil
}

// ListAccessors returns all token accessors from Vault.
func (s *LoginTokenScanner) ListAccessors() ([]string, error) {
	secret, err := s.client.vault.Auth().Token().ListAccessors()
	if err != nil {
		return nil, fmt.Errorf("vault: list accessors: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, nil
	}
	raw, ok := secret.Data["keys"]
	if !ok {
		return nil, nil
	}
	ifaces, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("vault: unexpected keys type")
	}
	accessors := make([]string, 0, len(ifaces))
	for _, v := range ifaces {
		if s, ok := v.(string); ok {
			accessors = append(accessors, s)
		}
	}
	return accessors, nil
}
