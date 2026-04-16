package vault

import (
	"context"
	"fmt"
	"time"
)

// SnapshotInfo holds metadata about a Vault raft snapshot.
type SnapshotInfo struct {
	TakenAt   time.Time
	SizeBytes int64
	Path      string
}

// SnapshotManager handles triggering and tracking Vault raft snapshots.
type SnapshotManager struct {
	client *Client
}

// NewSnapshotManager returns a new SnapshotManager.
func NewSnapshotManager(c *Client) (*SnapshotManager, error) {
	if c == nil {
		return nil, fmt.Errorf("vault client must not be nil")
	}
	return &SnapshotManager{client: c}, nil
}

// Take requests a raft snapshot from Vault and returns metadata.
func (s *SnapshotManager) Take(ctx context.Context) (*SnapshotInfo, error) {
	resp, err := s.client.Logical().ReadWithContext(ctx, "sys/storage/raft/snapshot")
	if err != nil {
		return nil, fmt.Errorf("snapshot request failed: %w", err)
	}
	if resp == nil {
		return nil, fmt.Errorf("empty response from snapshot endpoint")
	}

	info := &SnapshotInfo{
		TakenAt: time.Now().UTC(),
		Path:    "sys/storage/raft/snapshot",
	}

	if raw, ok := resp.Data["size"]; ok {
		if f, ok := raw.(float64); ok {
			info.SizeBytes = int64(f)
		}
	}

	return info, nil
}
