package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const opsGenieAPIURL = "https://api.opsgenie.com/v2/alerts"

// OpsGenieNotifier sends alerts to OpsGenie.
type OpsGenieNotifier struct {
	apiKey  string
	apiURL  string
	client  *http.Client
}

type opsGeniePayload struct {
	Message     string            `json:"message"`
	Description string            `json:"description"`
	P"priority"`
	Tags        []string          `json:"omitempty"`
	Details     map[string]string `json:"details,omitempty"`
}

// NewOpsGenieNotifier creates a new OpsGenieNotifier.
func NewOpsGenieNotifier(apiKey string, timeout time.Duration) *OpsGenieNotifier {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &OpsGenieNotifier{
		apiKey: apiKey,
		apiURL: opsGenieAPIURL,
		client: &http.Client{Timeout: timeout},
	}
}

// Send dispatches an alert notification to OpsGenie.
func (o *OpsGenieNotifier) Send(ctx context.Context, alert Alert) error {
	if o.apiKey == "" {
		return fmt.Errorf("opsgenie: api key is required")
	}

	priority := priorityFromSeverity(alert.Severity)
	payload := opsGeniePayload{
		Message:     fmt.Sprintf("Vault secret expiry: %s", alert.SecretPath),
		Description: alert.Message,
		Priority:    priority,
		Tags:        []string{"vault", "secret-expiry"},
		Details: map[string]string{
			"secret_path": alert.SecretPath,
			"severity":    alert.Severity,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("opsgenie: failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.apiURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("opsgenie: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "GenieKey "+o.apiKey)

	resp, err := o.client.Do(req)
	if err != nil {
		return fmt.Errorf("opsgenie: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("opsgenie: unexpected status code %d", resp.StatusCode)
	}
	return nil
}

func priorityFromSeverity(severity string) string {
	switch severity {
	case "critical":
		return "P1"
	case "warning":
		return "P3"
	default:
		return "P5"
	}
}
