package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// MFAMethod represents a configured MFA method in Vault.
type MFAMethod struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	MountAccessor string        `json:"mount_accessor"`
	Config     map[string]string `json:"config"`
	CreatedAt  time.Time         `json:"created_time"`
}

// MFAScanner lists and inspects MFA methods configured in Vault.
type MFAScanner struct {
	client *Client
}

// NewMFAScanner returns a new MFAScanner or an error if the client is nil.
func NewMFAScanner(c *Client) (*MFAScanner, error) {
	if c == nil {
		return nil, fmt.Errorf("mfa scanner: client must not be nil")
	}
	return &MFAScanner{client: c}, nil
}

// ListMethods returns all MFA methods configured under the identity MFA path.
func (s *MFAScanner) ListMethods() ([]MFAMethod, error) {
	req, err := http.NewRequest(http.MethodGet, s.client.address+"/v1/identity/mfa/method", nil)
	if err != nil {
		return nil, fmt.Errorf("mfa list: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", s.client.token)

	resp, err := s.client.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mfa list: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mfa list: unexpected status %d", resp.StatusCode)
	}

	var envelope struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("mfa list: decode: %w", err)
	}

	var methods []MFAMethod
	for _, key := range envelope.Data.Keys {
		m, err := s.GetMethod(key)
		if err != nil {
			continue
		}
		methods = append(methods, *m)
	}
	return methods, nil
}

// GetMethod retrieves a single MFA method by ID.
func (s *MFAScanner) GetMethod(id string) (*MFAMethod, error) {
	if id == "" {
		return nil, fmt.Errorf("mfa get: id must not be empty")
	}
	req, err := http.NewRequest(http.MethodGet, s.client.address+"/v1/identity/mfa/method/"+id, nil)
	if err != nil {
		return nil, fmt.Errorf("mfa get: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", s.client.token)

	resp, err := s.client.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mfa get: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("mfa get: method %q not found", id)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mfa get: unexpected status %d", resp.StatusCode)
	}

	var envelope struct {
		Data MFAMethod `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("mfa get: decode: %w", err)
	}
	return &envelope.Data, nil
}
