package vault

import (
	"encoding/json"
	"fmt"
	"time"
)

// AWSCredential represents a dynamic AWS credential lease from Vault.
type AWSCredential struct {
	LeaseID       string
	AccessKey     string
	SecretKey     string
	LeaseExpiry   time.Time
	Renewable     bool
}

// IsExpired returns true if the credential lease has expired.
func (a *AWSCredential) IsExpired() bool {
	return time.Now().After(a.LeaseExpiry)
}

// TimeUntilExpiry returns the duration until the credential expires.
func (a *AWSCredential) TimeUntilExpiry() time.Duration {
	return time.Until(a.LeaseExpiry)
}

// AWSScanner scans Vault AWS secret engine roles and credentials.
type AWSScanner struct {
	client *Client
	mount  string
}

// NewAWSScanner creates a new AWSScanner. Defaults mount to "aws".
func NewAWSScanner(client *Client, mount string) *AWSScanner {
	if client == nil {
		return nil
	}
	if mount == "" {
		mount = "aws"
	}
	return &AWSScanner{client: client, mount: mount}
}

// ListRoles returns all AWS roles configured under the mount.
func (s *AWSScanner) ListRoles() ([]string, error) {
	path := fmt.Sprintf("%s/roles", s.mount)
	resp, err := s.client.RawList(path)
	if err != nil {
		return nil, fmt.Errorf("aws list roles: %w", err)
	}
	var result struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("aws list roles decode: %w", err)
	}
	return result.Data.Keys, nil
}

// GetRole returns metadata for a named AWS role.
func (s *AWSScanner) GetRole(name string) (map[string]interface{}, error) {
	if name == "" {
		return nil, fmt.Errorf("aws role name must not be empty")
	}
	path := fmt.Sprintf("%s/roles/%s", s.mount, name)
	resp, err := s.client.RawRead(path)
	if err != nil {
		return nil, fmt.Errorf("aws get role: %w", err)
	}
	var result struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("aws get role decode: %w", err)
	}
	return result.Data, nil
}
