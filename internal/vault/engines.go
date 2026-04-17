package vault

import (
	"errors"
	"fmt"
)

// MountInfo represents a Vault secret engine mount.
type MountInfo struct {
	Path        string
	Type        string
	Description string
	Accessor    string
}

// EngineScanner lists enabled secret engines from Vault.
type EngineScanner struct {
	client *Client
}

// NewEngineScanner creates a new EngineScanner. Returns error if client is nil.
func NewEngineScanner(client *Client) (*EngineScanner, error) {
	if client == nil {
		return nil, errors.New("vault client must not be nil")
	}
	return &EngineScanner{client: client}, nil
}

// ListEngines returns all enabled secret engine mounts.
func (e *EngineScanner) ListEngines() ([]MountInfo, error) {
	secret, err := e.client.vc.Sys().ListMounts()
	if err != nil {
		return nil, fmt.Errorf("listing mounts: %w", err)
	}

	mounts := make([]MountInfo, 0, len(secret))
	for path, mount := range secret {
		mounts = append(mounts, MountInfo{
			Path:        path,
			Type:        mount.Type,
			Description: mount.Description,
			Accessor:    mount.Accessor,
		})
	}
	return mounts, nil
}
