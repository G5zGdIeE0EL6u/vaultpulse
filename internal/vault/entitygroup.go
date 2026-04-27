package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// EntityGroup represents a Vault identity group.
type EntityGroup struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Type     string    `json:"type"`
	Disabled bool      `json:"disabled"`
	Created  time.Time `json:"creation_time"`
	Modified time.Time `json:"last_update_time"`
}

// IsDisabled returns true if the group is disabled.
func (g *EntityGroup) IsDisabled() bool {
	return g.Disabled
}

// EntityGroupScanner scans Vault identity groups.
type EntityGroupScanner struct {
	client *Client
}

// NewEntityGroupScanner creates a new EntityGroupScanner.
// Returns nil if client is nil.
func NewEntityGroupScanner(client *Client) *EntityGroupScanner {
	if client == nil {
		return nil
	}
	return &EntityGroupScanner{client: client}
}

// ListGroups returns all identity group IDs from Vault.
func (s *EntityGroupScanner) ListGroups() ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, s.client.address+"/v1/identity/group/id?list=true", nil)
	if err != nil {
		return nil, fmt.Errorf("entitygroup: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", s.client.token)

	resp, err := s.client.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("entitygroup: list request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("entitygroup: unexpected status %d", resp.StatusCode)
	}

	var body struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("entitygroup: decode response: %w", err)
	}
	return body.Data.Keys, nil
}

// GetGroup retrieves a single identity group by ID.
func (s *EntityGroupScanner) GetGroup(id string) (*EntityGroup, error) {
	if id == "" {
		return nil, fmt.Errorf("entitygroup: id must not be empty")
	}

	req, err := http.NewRequest(http.MethodGet, s.client.address+"/v1/identity/group/id/"+id, nil)
	if err != nil {
		return nil, fmt.Errorf("entitygroup: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", s.client.token)

	resp, err := s.client.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("entitygroup: get request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("entitygroup: unexpected status %d", resp.StatusCode)
	}

	var body struct {
		Data EntityGroup `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("entitygroup: decode response: %w", err)
	}
	return &body.Data, nil
}
