package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// WebhookPayload represents the JSON body sent to a webhook endpoint.
type WebhookPayload struct {
	Timestamp time.Time `json:"timestamp"`
	SecretPath string    `json:"secret_path"`
	Severity   string    `json:"severity"`
	Message    string    `json:"message"`
	TTL        int64     `json:"ttl_seconds"`
}

// WebhookNotifier sends alert payloads to a configured HTTP endpoint.
type WebhookNotifier struct {
	URL     string
	Timeout time.Duration
	client  *http.Client
}

// NewWebhookNotifier creates a WebhookNotifier with the given URL and timeout.
func NewWebhookNotifier(url string, timeout time.Duration) *WebhookNotifier {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &WebhookNotifier{
		URL:     url,
		Timeout: timeout,
		client:  &http.Client{Timeout: timeout},
	}
}

// Send marshals the payload and POSTs it to the webhook URL.
func (w *WebhookNotifier) Send(payload WebhookPayload) error {
	if w.URL == "" {
		return fmt.Errorf("webhook URL is not configured")
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	resp, err := w.client.Post(w.URL, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("webhook POST failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("webhook returned non-2xx status: %d, body: %s", resp.StatusCode, bytes.TrimSpace(body))
	}

	return nil
}
