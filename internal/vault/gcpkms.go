package vault

import (
	"encoding/json"
	"fmt"
	"time"
)

// GCPKMSKey represents a GCP KMS key managed by Vault.
type GCPKMSKey struct {
	Name        string    `json:"name"`
	KeyRing     string    `json:"key_ring"`
	CryptoKey   string    `json:"crypto_key"`
	RotationPeriod int64  `json:"rotation_period"` // seconds
	LastRotated time.Time `json:"last_rotated"`
}

// DueForRotation returns true if the key has exceeded its rotation period.
func (k *GCPKMSKey) DueForRotation() bool {
	if k.RotationPeriod <= 0 {
		return false
	}
	return time.Since(k.LastRotated) >= time.Duration(k.RotationPeriod)*time.Second
}

// TimeUntilRotation returns the duration until the next rotation is due.
func (k *GCPKMSKey) TimeUntilRotation() time.Duration {
	if k.RotationPeriod <= 0 {
		return 0
	}
	next := k.LastRotated.Add(time.Duration(k.RotationPeriod) * time.Second)
	return time.Until(next)
}

// GCPKMSScanner scans Vault's GCP KMS secrets engine for key metadata.
type GCPKMSScanner struct {
	client *Client
	mount  string
}

// NewGCPKMSScanner creates a new GCPKMSScanner. Returns an error if client is nil.
func NewGCPKMSScanner(client *Client, mount string) (*GCPKMSScanner, error) {
	if client == nil {
		return nil, fmt.Errorf("gcpkms: client must not be nil")
	}
	if mount == "" {
		mount = "gcpkms"
	}
	return &GCPKMSScanner{client: client, mount: mount}, nil
}

// ListKeys returns the list of key names registered under the GCP KMS mount.
func (s *GCPKMSScanner) ListKeys() ([]string, error) {
	path := fmt.Sprintf("%s/keys", s.mount)
	body, err := s.client.List(path)
	if err != nil {
		return nil, fmt.Errorf("gcpkms: list keys: %w", err)
	}
	var resp struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("gcpkms: parse list response: %w", err)
	}
	return resp.Data.Keys, nil
}

// GetKey retrieves metadata for a single GCP KMS key by name.
func (s *GCPKMSScanner) GetKey(name string) (*GCPKMSKey, error) {
	if name == "" {
		return nil, fmt.Errorf("gcpkms: key name must not be empty")
	}
	path := fmt.Sprintf("%s/keys/%s", s.mount, name)
	body, err := s.client.Read(path)
	if err != nil {
		return nil, fmt.Errorf("gcpkms: get key %q: %w", name, err)
	}
	var resp struct {
		Data GCPKMSKey `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("gcpkms: parse key response: %w", err)
	}
	resp.Data.Name = name
	return &resp.Data, nil
}
