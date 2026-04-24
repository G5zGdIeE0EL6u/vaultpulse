package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// HAStatus represents the high-availability status of a Vault cluster.
type HAStatus struct {
	Enabled     bool   `json:"ha_enabled"`
	Leader      bool   `json:"is_self"`
	LeaderAddr  string `json:"leader_address"`
	ClusterName string `json:"cluster_name"`
	ClusterID   string `json:"cluster_id"`
}

// HAChecker checks the HA status of a Vault instance.
type HAChecker struct {
	client *Client
}

// NewHAChecker creates a new HAChecker. Returns an error if the client is nil.
func NewHAChecker(client *Client) (*HAChecker, error) {
	if client == nil {
		return nil, fmt.Errorf("vault client must not be nil")
	}
	return &HAChecker{client: client}, nil
}

// Status queries the Vault HA status endpoint and returns the result.
func (h *HAChecker) Status() (*HAStatus, error) {
	req, err := http.NewRequest(http.MethodGet, h.client.address+"/v1/sys/leader", nil)
	if err != nil {
		return nil, fmt.Errorf("building ha status request: %w", err)
	}
	req.Header.Set("X-Vault-Token", h.client.token)

	resp, err := h.client.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing ha status request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ha status returned non-200 status: %d", resp.StatusCode)
	}

	var status HAStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("decoding ha status response: %w", err)
	}
	return &status, nil
}
