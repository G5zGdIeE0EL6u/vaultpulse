package vault

import (
	"fmt"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// Client wraps the Vault API client with vaultpulse-specific helpers.
type Client struct {
	api *vaultapi.Client
}

// NewClient creates a new Vault client using the provided address and token.
func NewClient(address, token string) (*Client, error) {
	cfg := vaultapi.DefaultConfig()
	cfg.Address = address

	api, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating vault api client: %w", err)
	}

	api.SetToken(token)

	return &Client{api: api}, nil
}

// IsHealthy returns true if the Vault server is reachable and unsealed.
func (c *Client) IsHealthy() (bool, error) {
	health, err := c.api.Sys().Health()
	if err != nil {
		return false, fmt.Errorf("checking vault health: %w", err)
	}
	return !health.Sealed && health.Initialized, nil
}

// SecretInfo holds metadata about a KV secret.
type SecretInfo struct {
	Path      string
	ExpiresAt *time.Time
	TTL       time.Duration
	LeaseID   string
}

// ReadSecret reads a secret at the given path and returns its info.
func (c *Client) ReadSecret(path string) (*SecretInfo, error) {
	secret, err := c.api.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("reading secret at %q: %w", path, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("secret not found at path %q", path)
	}

	info := &SecretInfo{
		Path:    path,
		LeaseID: secret.LeaseID,
	}

	if secret.LeaseDuration > 0 {
		ttl := time.Duration(secret.LeaseDuration) * time.Second
		info.TTL = ttl
		expiry := time.Now().Add(ttl)
		info.ExpiresAt = &expiry
	}

	return info, nil
}

// RenewLease attempts to renew a lease by its ID.
func (c *Client) RenewLease(leaseID string, increment int) error {
	_, err := c.api.Sys().Renew(leaseID, increment)
	if err != nil {
		return fmt.Errorf("renewing lease %q: %w", leaseID, err)
	}
	return nil
}
