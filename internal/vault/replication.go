package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ReplicationStatus holds the DR and performance replication state.
type ReplicationStatus struct {
	DRMode          string `json:"dr_mode"`
	PerformanceMode string `json:"performance_mode"`
	DRPrimary       bool   `json:"dr_primary"`
	PerfPrimary     bool   `json:"perf_primary"`
	Connected       bool   `json:"connected"`
	LastWAL         uint64 `json:"last_wal"`
}

// ReplicationChecker queries Vault replication status.
type ReplicationChecker struct {
	client *Client
}

// NewReplicationChecker returns a new ReplicationChecker or an error if client is nil.
func NewReplicationChecker(c *Client) (*ReplicationChecker, error) {
	if c == nil {
		return nil, fmt.Errorf("vault client must not be nil")
	}
	return &ReplicationChecker{client: c}, nil
}

// Status fetches the current replication status from Vault.
func (r *ReplicationChecker) Status() (*ReplicationStatus, error) {
	req, err := http.NewRequest(http.MethodGet, r.client.address+"/v1/sys/replication/status", nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("X-Vault-Token", r.client.token)

	resp, err := r.client.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var payload struct {
		Data struct {
			DR struct {
				Mode    string `json:"mode"`
				Primary bool   `json:"primary"`
				LastWAL uint64 `json:"last_wal"`
			} `json:"dr"`
			Performance struct {
				Mode    string `json:"mode"`
				Primary bool   `json:"primary"`
			} `json:"performance"`
			Connected bool `json:"connected"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &ReplicationStatus{
		DRMode:          payload.Data.DR.Mode,
		PerformanceMode: payload.Data.Performance.Mode,
		DRPrimary:       payload.Data.DR.Primary,
		PerfPrimary:     payload.Data.Performance.Primary,
		Connected:       payload.Data.Connected,
		LastWAL:         payload.Data.DR.LastWAL,
	}, nil
}
