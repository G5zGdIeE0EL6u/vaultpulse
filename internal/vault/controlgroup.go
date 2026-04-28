package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ControlGroupRequest represents a Vault control group authorization request.
type ControlGroupRequest struct {
	Accessor  string    `json:"accessor"`
	Path      string    `json:"path"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Approved  bool      `json:"approved"`
}

// IsExpired returns true if the control group request has passed its expiry.
func (c *ControlGroupRequest) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}

// TimeUntilExpiry returns the duration until the request expires.
func (c *ControlGroupRequest) TimeUntilExpiry() time.Duration {
	return time.Until(c.ExpiresAt)
}

// ControlGroupScanner queries Vault for pending control group requests.
type ControlGroupScanner struct {
	client *Client
}

// NewControlGroupScanner creates a new ControlGroupScanner.
// Returns nil if client is nil.
func NewControlGroupScanner(client *Client) *ControlGroupScanner {
	if client == nil {
		return nil
	}
	return &ControlGroupScanner{client: client}
}

// GetRequest fetches a control group request by accessor from Vault.
func (s *ControlGroupScanner) GetRequest(accessor string) (*ControlGroupRequest, error) {
	if accessor == "" {
		return nil, fmt.Errorf("controlgroup: accessor must not be empty")
	}
	path := fmt.Sprintf("/v1/sys/control-group/request")
	body := map[string]string{"accessor": accessor}
	b, _ := json.Marshal(body)

	resp, err := s.client.RawPost(path, b)
	if err != nil {
		return nil, fmt.Errorf("controlgroup: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("controlgroup: accessor %q not found", accessor)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("controlgroup: unexpected status %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			Accessor  string `json:"accessor"`
			Path      string `json:"creation_path"`
			CreatedAt string `json:"creation_time"`
			ExpiresAt string `json:"expiration_time"`
			Approved  bool   `json:"approved"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("controlgroup: decode error: %w", err)
	}

	created, _ := time.Parse(time.RFC3339, result.Data.CreatedAt)
	expires, _ := time.Parse(time.RFC3339, result.Data.ExpiresAt)

	return &ControlGroupRequest{
		Accessor:  result.Data.Accessor,
		Path:      result.Data.Path,
		CreatedAt: created,
		ExpiresAt: expires,
		Approved:  result.Data.Approved,
	}, nil
}
