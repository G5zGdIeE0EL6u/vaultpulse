package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// EntityAlias represents a Vault identity entity alias.
type EntityAlias struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	MountType    string    `json:"mount_type"`
	MountPath    string    `json:"mount_path"`
	CreationTime time.Time `json:"creation_time"`
	LastUpdateTime time.Time `json:"last_update_time"`
}

// EntityAliasScanner scans Vault identity entity aliases.
type EntityAliasScanner struct {
	client *Client
}

// NewEntityAliasScanner returns a new EntityAliasScanner or an error if client is nil.
func NewEntityAliasScanner(client *Client) (*EntityAliasScanner, error) {
	if client == nil {
		return nil, fmt.Errorf("vault client must not be nil")
	}
	return &EntityAliasScanner{client: client}, nil
}

// ListAliases returns all entity aliases from the Vault identity store.
func (s *EntityAliasScanner) ListAliases() ([]EntityAlias, error) {
	req, err := http.NewRequest(http.MethodList, s.client.address+"/v1/identity/entity-alias/id", nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("X-Vault-Token", s.client.token)

	resp, err := s.client.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			KeyInfo map[string]EntityAlias `json:"key_info"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	aliases := make([]EntityAlias, 0, len(result.Data.KeyInfo))
	for id, alias := range result.Data.KeyInfo {
		alias.ID = id
		aliases = append(aliases, alias)
	}
	return aliases, nil
}
