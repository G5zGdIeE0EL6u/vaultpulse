package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// QuotaInfo holds rate limit quota details for a Vault path.
type QuotaInfo struct {
	Name          string  `json:"name"`
	Path          string  `json:"path"`
	Type          string  `json:"type"`
	Rate          float64 `json:"rate"`
	Interval      float64 `json:"interval"`
	BlockInterval float64 `json:"block_interval"`
}

// QuotaChecker lists and retrieves rate limit quotas from Vault.
type QuotaChecker struct {
	client *Client
}

// NewQuotaChecker returns a new QuotaChecker or an error if client is nil.
func NewQuotaChecker(c *Client) (*QuotaChecker, error) {
	if c == nil {
		return nil, fmt.Errorf("vault client must not be nil")
	}
	return &QuotaChecker{client: c}, nil
}

// ListQuotas returns the names of all rate limit quotas configured in Vault.
func (q *QuotaChecker) ListQuotas() ([]string, error) {
	resp, err := q.client.raw(http.MethodGet, "/v1/sys/quotas/rate-limit?list=true", nil)
	if err != nil {
		return nil, fmt.Errorf("listing quotas: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	var out struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decoding quota list: %w", err)
	}
	return out.Data.Keys, nil
}

// GetQuota returns details for the named rate limit quota.
func (q *QuotaChecker) GetQuota(name string) (*QuotaInfo, error) {
	if name == "" {
		return nil, fmt.Errorf("quota name must not be empty")
	}
	resp, err := q.client.raw(http.MethodGet, "/v1/sys/quotas/rate-limit/"+name, nil)
	if err != nil {
		return nil, fmt.Errorf("getting quota %q: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("quota %q not found", name)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	var out struct {
		Data QuotaInfo `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decoding quota: %w", err)
	}
	return &out.Data, nil
}
