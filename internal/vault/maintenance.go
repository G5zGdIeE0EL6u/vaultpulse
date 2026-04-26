package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// MaintenanceStatus holds the current maintenance mode state of a Vault node.
type MaintenanceStatus struct {
	Enabled       bool      `json:"maintenance_mode"`
	RequestID     string    `json:"request_id"`
	RetrievedAt   time.Time `json:"-"`
}

// IsInMaintenance returns true when maintenance mode is active.
func (m *MaintenanceStatus) IsInMaintenance() bool {
	if m == nil {
		return false
	}
	return m.Enabled
}

// Age returns how long ago the maintenance status was retrieved.
// It returns zero if the status is nil or was never fetched.
func (m *MaintenanceStatus) Age() time.Duration {
	if m == nil || m.RetrievedAt.IsZero() {
		return 0
	}
	return time.Since(m.RetrievedAt)
}

// MaintenanceChecker queries the Vault maintenance endpoint.
type MaintenanceChecker struct {
	client *Client
}

// NewMaintenanceChecker returns a new MaintenanceChecker or an error if client is nil.
func NewMaintenanceChecker(c *Client) (*MaintenanceChecker, error) {
	if c == nil {
		return nil, fmt.Errorf("vault client must not be nil")
	}
	return &MaintenanceChecker{client: c}, nil
}

// Status fetches the current maintenance mode status from Vault.
func (mc *MaintenanceChecker) Status() (*MaintenanceStatus, error) {
	req, err := http.NewRequest(http.MethodGet, mc.client.address+"/v1/sys/maintenance", nil)
	if err != nil {
		return nil, fmt.Errorf("building maintenance request: %w", err)
	}
	req.Header.Set("X-Vault-Token", mc.client.token)

	resp, err := mc.client.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("maintenance request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from maintenance endpoint", resp.StatusCode)
	}

	var status MaintenanceStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("decoding maintenance response: %w", err)
	}
	status.RetrievedAt = time.Now().UTC()
	return &status, nil
}
