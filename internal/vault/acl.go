package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ACLToken represents a Vault ACL token with metadata.
type ACLToken struct {
	Accessor   string    `json:"accessor"`
	DisplayName string   `json:"display_name"`
	Policies   []string  `json:"policies"`
	ExpireTime time.Time `json:"expire_time"`
	Orphan     bool      `json:"orphan"`
	Path       string    `json:"path"`
}

// IsExpired returns true if the token has passed its expiry time.
func (a *ACLToken) IsExpired() bool {
	if a.ExpireTime.IsZero() {
		return false
	}
	return time.Now().After(a.ExpireTime)
}

// TimeUntilExpiry returns the duration until the token expires.
func (a *ACLToken) TimeUntilExpiry() time.Duration {
	if a.ExpireTime.IsZero() {
		return 0
	}
	return time.Until(a.ExpireTime)
}

// ACLScanner scans Vault ACL tokens.
type ACLScanner struct {
	client *Client
}

// NewACLScanner creates a new ACLScanner. Returns nil if client is nil.
func NewACLScanner(client *Client) *ACLScanner {
	if client == nil {
		return nil
	}
	return &ACLScanner{client: client}
}

// LookupAccessor retrieves token metadata for the given accessor.
func (s *ACLScanner) LookupAccessor(accessor string) (*ACLToken, error) {
	if accessor == "" {
		return nil, fmt.Errorf("accessor must not be empty")
	}

	body := map[string]string{"accessor": accessor}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal accessor: %w", err)
	}

	resp, err := s.client.RawPost("/v1/auth/token/lookup-accessor", b)
	if err != nil {
		return nil, fmt.Errorf("lookup accessor: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("accessor not found: %s", accessor)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var result struct {
		Data ACLToken `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &result.Data, nil
}
