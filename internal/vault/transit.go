package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// TransitKey holds metadata about a Vault transit encryption key.
type TransitKey struct {
	Name            string
	Type            string
	DeletionAllowed bool
	Exportable      bool
	LatestVersion   int
}

// TransitScanner lists and inspects transit engine keys.
type TransitScanner struct {
	client *Client
	mount  string
}

// NewTransitScanner returns a TransitScanner for the given mount path.
func NewTransitScanner(c *Client, mount string) *TransitScanner {
	if mount == "" {
		mount = "transit"
	}
	return &TransitScanner{client: c, mount: mount}
}

// ListKeys returns all key names found in the transit mount.
func (ts *TransitScanner) ListKeys(ctx context.Context) ([]string, error) {
	if ts.client == nil {
		return nil, fmt.Errorf("transit: nil client")
	}
	path := fmt.Sprintf("/v1/%s/keys?list=true", ts.mount)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.client.address+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", ts.client.token)
	resp, err := ts.client.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return []string{}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("transit: list keys status %d", resp.StatusCode)
	}
	var body struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	return body.Data.Keys, nil
}

// GetKey returns metadata for a single transit key.
func (ts *TransitScanner) GetKey(ctx context.Context, name string) (*TransitKey, error) {
	if name == "" {
		return nil, fmt.Errorf("transit: key name required")
	}
	path := fmt.Sprintf("/v1/%s/keys/%s", ts.mount, name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.client.address+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", ts.client.token)
	resp, err := ts.client.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("transit: key %q not found", name)
	}
	var body struct {
		Data struct {
			Type            string `json:"type"`
			DeletionAllowed bool   `json:"deletion_allowed"`
			Exportable      bool   `json:"exportable"`
			LatestVersion   int    `json:"latest_version"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	return &TransitKey{
		Name:            name,
		Type:            body.Data.Type,
		DeletionAllowed: body.Data.DeletionAllowed,
		Exportable:      body.Data.Exportable,
		LatestVersion:   body.Data.LatestVersion,
	}, nil
}
