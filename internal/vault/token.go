package vault

import (
	"context"
	"fmt"
	"time"
)

// TokenInfo holds metadata about a Vault token.
type TokenInfo struct {
	Accessor   string
	TTL        time.Duration
	Renewable  bool
	Policies   []string
	ExpireTime time.Time
}

// IsExpired returns true if the token has expired.
func (t *TokenInfo) IsExpired() bool {
	return time.Now().After(t.ExpireTime)
}

// TimeUntilExpiry returns the duration until the token expires.
func (t *TokenInfo) TimeUntilExpiry() time.Duration {
	return time.Until(t.ExpireTime)
}

// TokenInspector inspects and manages Vault token metadata.
type TokenInspector struct {
	client *Client
}

// NewTokenInspector creates a new TokenInspector.
func NewTokenInspector(c *Client) *TokenInspector {
	return &TokenInspector{client: c}
}

// LookupSelf retrieves token info for the currently authenticated token.
func (ti *TokenInspector) LookupSelf(ctx context.Context) (*TokenInfo, error) {
	secret, err := ti.client.vault.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("token lookup failed: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("empty token data returned")
	}

	ttlRaw, ok := secret.Data["ttl"]
	if !ok {
		return nil, fmt.Errorf("ttl missing from token data")
	}
	ttlVal, ok := ttlRaw.(json.Number)
	if !ok {
		return nil, fmt.Errorf("unexpected ttl type")
	}
	ttlSec, err := ttlVal.Int64()
	if err != nil {
		return nil, fmt.Errorf("parsing ttl: %w", err)
	}

	policies, _ := secret.TokenPolicies()
	accessor, _ := secret.TokenAccessor()
	renewable, _ := secret.TokenIsRenewable()

	ttl := time.Duration(ttlSec) * time.Second
	return &TokenInfo{
		Accessor:   accessor,
		TTL:        ttl,
		Renewable:  renewable,
		Policies:   policies,
		ExpireTime: time.Now().Add(ttl),
	}, nil
}
