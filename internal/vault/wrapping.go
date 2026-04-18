package vault

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// WrappedSecret holds information about a response-wrapped secret token.
type WrappedSecret struct {
	Token     string
	TTL       time.Duration
	CreatedAt time.Time
	Accessor  string
}

// IsExpired returns true if the wrapping token TTL has elapsed.
func (w *WrappedSecret) IsExpired() bool {
	return time.Now().After(w.CreatedAt.Add(w.TTL))
}

// TimeUntilExpiry returns the remaining duration before the wrapping token expires.
func (w *WrappedSecret) TimeUntilExpiry() time.Duration {
	return time.Until(w.CreatedAt.Add(w.TTL))
}

// WrappingManager handles response-wrapping operations against Vault.
type WrappingManager struct {
	client *Client
}

// NewWrappingManager creates a new WrappingManager. Returns an error if client is nil.
func NewWrappingManager(client *Client) (*WrappingManager, error) {
	if client == nil {
		return nil, errors.New("vault client must not be nil")
	}
	return &WrappingManager{client: client}, nil
}

// Lookup queries Vault for metadata about a wrapping token.
func (wm *WrappingManager) Lookup(ctx context.Context, token string) (*WrappedSecret, error) {
	if token == "" {
		return nil, errors.New("wrapping token must not be empty")
	}

	path := "sys/wrapping/lookup"
	body := map[string]interface{}{"token": token}

	resp, err := wm.client.RawPost(ctx, path, body)
	if err != nil {
		return nil, fmt.Errorf("wrapping lookup failed: %w", err)
	}

	data, ok := resp["data"].(map[string]interface{})
	if !ok {
		return nil, errors.New("unexpected response format from wrapping lookup")
	}

	ttlRaw, _ := data["ttl"].(float64)
	accessor, _ := data["accessor"].(string)
	creationStr, _ := data["creation_time"].(string)

	createdAt := time.Now()
	if creationStr != "" {
		if t, err := time.Parse(time.RFC3339, creationStr); err == nil {
			createdAt = t
		}
	}

	return &WrappedSecret{
		Token:     token,
		TTL:       time.Duration(ttlRaw) * time.Second,
		CreatedAt: createdAt,
		Accessor:  accessor,
	}, nil
}
