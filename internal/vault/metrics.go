package vault

import (
	"fmt"
	"time"
)

// MetricPoint represents a single collected metric from Vault.
type MetricPoint struct {
	Name      string
	Value     float64
	Labels    map[string]string
	Timestamp time.Time
}

// MetricsCollector reads telemetry data from a Vault instance.
type MetricsCollector struct {
	client *Client
}

// NewMetricsCollector creates a MetricsCollector. Returns an error if client is nil.
func NewMetricsCollector(client *Client) (*MetricsCollector, error) {
	if client == nil {
		return nil, fmt.Errorf("vault client must not be nil")
	}
	return &MetricsCollector{client: client}, nil
}

// Collect fetches the current metrics summary from Vault's sys/metrics endpoint.
func (mc *MetricsCollector) Collect() ([]MetricPoint, error) {
	path := "/v1/sys/metrics?format=prometheus"
	resp, err := mc.client.RawGet(path)
	if err != nil {
		return nil, fmt.Errorf("metrics collect: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("metrics collect: unexpected status %d", resp.StatusCode)
	}

	// Return a synthetic point indicating the collection succeeded.
	points := []MetricPoint{
		{
			Name:      "vault_up",
			Value:     1,
			Labels:    map[string]string{"source": "sys/metrics"},
			Timestamp: time.Now().UTC(),
		},
	}
	return points, nil
}
