package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ReplicationStatus holds DR and performance replication state.
type ReplicationStatus struct {
	DRMode    string
	DRState   string
	PerfMode  string
	PerfState string
}

// ReplicationChecker queries Vault replication status.
type ReplicationChecker struct {
	client *Client
}

// NewReplicationChecker returns a new ReplicationChecker.
func NewReplicationChecker(c *Client) (*ReplicationChecker, error) {
	if c == nil {
		return nil, fmt.Errorf("vault client is required")
	}
	return &ReplicationChecker{client: c}, nil
}

// Status fetches the current replication status from Vault.
func (r *ReplicationChecker) Status() (*ReplicationStatus, error) {
	req, err := http.NewRequest(http.MethodGet, r.client.Address+"/v1/sys/replication/status", nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("X-Vault-Token", r.client.Token)

	resp, err := r.client.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var raw struct {
		Data struct {
			DR struct {
				Mode  string `json:"mode"`
				State string `json:"state"`
			} `json:"dr"`
			Performance struct {
				Mode  string `json:"mode"`
				State string `json:"state"`
			} `json:"performance"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &ReplicationStatus{
		DRMode:    raw.Data.DR.Mode,
		DRState:   raw.Data.DR.State,
		PerfMode:  raw.Data.Performance.Mode,
		PerfState: raw.Data.Performance.State,
	}, nil
}
