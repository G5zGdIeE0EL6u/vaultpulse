package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// RaftPeer represents a single peer in the Raft cluster.
type RaftPeer struct {
	NodeID    string `json:"node_id"`
	Address   string `json:"address"`
	Leader    bool   `json:"leader"`
	Protocol  string `json:"protocol_version"`
	Voter     bool   `json:"voter"`
}

// RaftStatus holds the Raft cluster configuration.
type RaftStatus struct {
	Index   uint64      `json:"index"`
	Peers   []RaftPeer  `json:"servers"`
}

// RaftChecker queries Vault's Raft storage backend.
type RaftChecker struct {
	client *Client
}

// NewRaftChecker creates a RaftChecker. Returns an error if client is nil.
func NewRaftChecker(c *Client) (*RaftChecker, error) {
	if c == nil {
		return nil, fmt.Errorf("raft: client must not be nil")
	}
	return &RaftChecker{client: c}, nil
}

// Status fetches the current Raft configuration from Vault.
func (r *RaftChecker) Status(ctx context.Context) (*RaftStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		r.client.address+"/v1/sys/storage/raft/configuration", nil)
	if err != nil {
		return nil, fmt.Errorf("raft: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", r.client.token)

	resp, err := r.client.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("raft: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("raft: unexpected status %d", resp.StatusCode)
	}

	var wrapper struct {
		Data RaftStatus `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("raft: decode response: %w", err)
	}
	return &wrapper.Data, nil
}
