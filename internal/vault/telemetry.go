package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// TelemetrySample holds a single snapshot of Vault telemetry counters.
type TelemetrySample struct {
	Timestamp    time.Time
	LeaseCount   int64
	TokenCount   int64
	RequestCount int64
	ErrorCount   int64
}

// TelemetryCollector fetches runtime telemetry from Vault's sys/metrics endpoint.
type TelemetryCollector struct {
	client *Client
}

// NewTelemetryCollector returns a TelemetryCollector or an error if client is nil.
func NewTelemetryCollector(c *Client) (*TelemetryCollector, error) {
	if c == nil {
		return nil, fmt.Errorf("telemetry: client must not be nil")
	}
	return &TelemetryCollector{client: c}, nil
}

// Collect queries /v1/sys/metrics?format=json and returns a TelemetrySample.
func (tc *TelemetryCollector) Collect() (*TelemetrySample, error) {
	req, err := http.NewRequest(http.MethodGet, tc.client.Address+"/v1/sys/metrics?format=json", nil)
	if err != nil {
		return nil, fmt.Errorf("telemetry: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", tc.client.Token)

	resp, err := tc.client.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("telemetry: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("telemetry: unexpected status %d", resp.StatusCode)
	}

	var raw struct {
		Counters []struct {
			Name  string  `json:"Name"`
			Count float64 `json:"Count"`
		} `json:"Counters"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("telemetry: decode response: %w", err)
	}

	sample := &TelemetrySample{Timestamp: time.Now()}
	for _, c := range raw.Counters {
		switch c.Name {
		case "vault.expire.num_leases":
			sample.LeaseCount = int64(c.Count)
		case "vault.token.count":
			sample.TokenCount = int64(c.Count)
		case "vault.core.handle_request":
			sample.RequestCount = int64(c.Count)
		case "vault.core.handle_error":
			sample.ErrorCount = int64(c.Count)
		}
	}
	return sample, nil
}
