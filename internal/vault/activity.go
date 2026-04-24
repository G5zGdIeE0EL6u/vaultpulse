package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ActivityRecord represents a single client activity entry from Vault's
// activity log endpoint.
type ActivityRecord struct {
	ClientID   string    `json:"client_id"`
	Namespace  string    `json:"namespace_id"`
	MountPath  string    `json:"mount_accessor"`
	Timestamp  time.Time `json:"timestamp"`
	EntityID   string    `json:"entity_id"`
}

// ActivitySummary holds aggregated activity data for a billing period.
type ActivitySummary struct {
	StartTime      time.Time       `json:"start_time"`
	EndTime        time.Time       `json:"end_time"`
	DistinctEntities int           `json:"distinct_entities"`
	DistinctNonEntities int        `json:"distinct_non_entity_tokens"`
	Records        []ActivityRecord `json:"by_namespace"`
}

// ActivityChecker queries Vault's activity log API.
type ActivityChecker struct {
	client *Client
}

// NewActivityChecker returns a new ActivityChecker. Returns an error if
// client is nil.
func NewActivityChecker(client *Client) (*ActivityChecker, error) {
	if client == nil {
		return nil, fmt.Errorf("activity: client must not be nil")
	}
	return &ActivityChecker{client: client}, nil
}

// GetSummary fetches the activity summary for the given start/end window.
// Both times are formatted as RFC3339 query parameters.
func (a *ActivityChecker) GetSummary(start, end time.Time) (*ActivitySummary, error) {
	path := fmt.Sprintf(
		"/v1/sys/internal/counters/activity?start_time=%s&end_time=%s",
		start.UTC().Format(time.RFC3339),
		end.UTC().Format(time.RFC3339),
	)

	resp, err := a.client.RawClient().Get(a.client.Address() + path)
	if err != nil {
		return nil, fmt.Errorf("activity: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("activity: unexpected status %d", resp.StatusCode)
	}

	var envelope struct {
		Data ActivitySummary `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("activity: failed to decode response: %w", err)
	}

	return &envelope.Data, nil
}
