package vault

import (
	"context"
	"fmt"
)

// SealStatus represents the seal state of a Vault instance.
type SealStatus struct {
	Sealed      bool    `json:"sealed"`
	Initialized bool    `json:"initialized"`
	Progress    int     `json:"progress"`
	Threshold   int     `json:"t"`
	Shares      int     `json:"n"`
	Version     string  `json:"version"`
	ClusterName string  `json:"cluster_name"`
}

// SealChecker checks the seal status of a Vault instance.
type SealChecker struct {
	client *Client
}

// NewSealChecker creates a new SealChecker. Returns an error if client is nil.
func NewSealChecker(client *Client) (*SealChecker, error) {
	if client == nil {
		return nil, fmt.Errorf("vault client must not be nil")
	}
	return &SealChecker{client: client}, nil
}

// Status queries the Vault seal status endpoint and returns the result.
func (s *SealChecker) Status(ctx context.Context) (*SealStatus, error) {
	resp, err := s.client.Logical().ReadWithContext(ctx, "sys/seal-status")
	if err != nil {
		return nil, fmt.Errorf("querying seal status: %w", err)
	}
	if resp == nil {
		return nil, fmt.Errorf("empty response from seal-status endpoint")
	}

	sealed, _ := resp.Data["sealed"].(bool)
	initialized, _ := resp.Data["initialized"].(bool)
	version, _ := resp.Data["version"].(string)
	clusterName, _ := resp.Data["cluster_name"].(string)

	progress := 0
	if v, ok := resp.Data["progress"].(float64); ok {
		progress = int(v)
	}
	threshold := 0
	if v, ok := resp.Data["t"].(float64); ok {
		threshold = int(v)
	}
	shares := 0
	if v, ok := resp.Data["n"].(float64); ok {
		shares = int(v)
	}

	return &SealStatus{
		Sealed:      sealed,
		Initialized: initialized,
		Progress:    progress,
		Threshold:   threshold,
		Shares:      shares,
		Version:     version,
		ClusterName: clusterName,
	}, nil
}
