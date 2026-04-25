package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// IdentityEntity represents a Vault identity entity.
type IdentityEntity struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	CreationTime time.Time `json:"creation_time"`
	LastUpdateTime time.Time `json:"last_update_time"`
	MergedEntityIDs []string `json:"merged_entity_ids"`
	Disabled     bool      `json:"disabled"`
}

// IdentityScanner lists and retrieves identity entities from Vault.
type IdentityScanner struct {
	client *Client
}

// NewIdentityScanner creates a new IdentityScanner.
// Returns nil if client is nil.
func NewIdentityScanner(client *Client) *IdentityScanner {
	if client == nil {
		return nil
	}
	return &IdentityScanner{client: client}
}

// ListEntities returns a list of entity IDs from the identity store.
func (s *IdentityScanner) ListEntities() ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, s.client.address+"/v1/identity/entity/id?list=true", nil)
	if err != nil {
		return nil, fmt.Errorf("identity: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", s.client.token)

	resp, err := s.client.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("identity: list entities: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("identity: list entities: status %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("identity: decode list: %w", err)
	}
	return result.Data.Keys, nil
}

// GetEntity retrieves a single identity entity by ID.
func (s *IdentityScanner) GetEntity(id string) (*IdentityEntity, error) {
	if id == "" {
		return nil, fmt.Errorf("identity: entity id must not be empty")
	}
	req, err := http.NewRequest(http.MethodGet, s.client.address+"/v1/identity/entity/id/"+id, nil)
	if err != nil {
		return nil, fmt.Errorf("identity: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", s.client.token)

	resp, err := s.client.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("identity: get entity: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("identity: get entity %q: status %d", id, resp.StatusCode)
	}

	var result struct {
		Data IdentityEntity `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("identity: decode entity: %w", err)
	}
	return &result.Data, nil
}
