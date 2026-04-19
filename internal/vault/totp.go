package vault

import (
	"fmt"
	"time"

	"github.com/fvbock/vaultpulse/internal/vault"
)

// TOTPKey holds metadata about a TOTP key stored in Vault.
type TOTPKey struct {
	Name      string
	AccountID string
	Issuer    string
	Period    int
	CreatedAt time.Time
}

// IsExpired returns false — TOTP keys do not expire by default.
func (k *TOTPKey) IsExpired() bool { return false }

// TOTPScanner lists and retrieves TOTP keys from a Vault TOTP secrets engine.
type TOTPScanner struct {
	client *Client
	mount  string
}

// NewTOTPScanner creates a new TOTPScanner. Returns an error if client is nil.
func NewTOTPScanner(client *Client, mount string) (*TOTPScanner, error) {
	if client == nil {
		return nil, fmt.Errorf("totp: client must not be nil")
	}
	if mount == "" {
		mount = "totp"
	}
	return &TOTPScanner{client: client, mount: mount}, nil
}

// ListKeys returns the names of all TOTP keys under the configured mount.
func (s *TOTPScanner) ListKeys() ([]string, error) {
	path := fmt.Sprintf("%s/keys", s.mount)
	secret, err := s.client.vault.Logical().List(path)
	if err != nil {
		return nil, fmt.Errorf("totp: list keys: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}
	raw, ok := secret.Data["keys"]
	if !ok {
		return []string{}, nil
	}
	items, ok := raw.([]interface{})
	if !ok {
		return []string{}, nil
	}
	keys := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			keys = append(keys, s)
		}
	}
	return keys, nil
}

// GetKey retrieves metadata for a single TOTP key by name.
func (s *TOTPScanner) GetKey(name string) (*TOTPKey, error) {
	if name == "" {
		return nil, fmt.Errorf("totp: key name must not be empty")
	}
	path := fmt.Sprintf("%s/keys/%s", s.mount, name)
	secret, err := s.client.vault.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("totp: get key %q: %w", name, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("totp: key %q not found", name)
	}
	key := &TOTPKey{Name: name}
	if v, ok := secret.Data["issuer"].(string); ok {
		key.Issuer = v
	}
	if v, ok := secret.Data["account_name"].(string); ok {
		key.AccountID = v
	}
	if v, ok := secret.Data["period"].(int); ok {
		key.Period = v
	}
	return key, nil
}

// suppress unused import if vault package path differs
var _ = vault.NewClient
