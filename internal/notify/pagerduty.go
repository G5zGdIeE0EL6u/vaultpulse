package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const pagerDutyEventURL = "https://events.pagerduty.com/v2/enqueue"

// PagerDutyNotifier sends alerts to PagerDuty via the Events API v2.
type PagerDutyNotifier struct {
	integrationKey string
	client         *http.Client
}

type pagerDutyPayload struct {
	RoutingKey  string            `json:"routing_key"`
	EventAction string            `json:"event_action"`
	Payload     pagerDutyDetails  `json:"payload"`
	Links       []pagerDutyLink   `json:"links,omitempty"`
}

type pagerDutyDetails struct {
	Summary   string `json:"summary"`
	Source    string `json:"source"`
	Severity  string `json:"severity"`
	Timestamp string `json:"timestamp"`
}

type pagerDutyLink struct {
	Href string `json:"href"`
	Text string `json:"text"`
}

// NewPagerDutyNotifier creates a new PagerDutyNotifier with the given integration key.
func NewPagerDutyNotifier(integrationKey string, timeout time.Duration) *PagerDutyNotifier {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &PagerDutyNotifier{
		integrationKey: integrationKey,
		client:         &http.Client{Timeout: timeout},
	}
}

// Send dispatches an alert to PagerDuty. severity should be one of: critical, error, warning, info.
func (p *PagerDutyNotifier) Send(summary, source, severity string) error {
	if p.integrationKey == "" {
		return fmt.Errorf("pagerduty: integration key is required")
	}

	body := pagerDutyPayload{
		RoutingKey:  p.integrationKey,
		EventAction: "trigger",
		Payload: pagerDutyDetails{
			Summary:   summary,
			Source:    source,
			Severity:  severity,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	}

	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("pagerduty: failed to marshal payload: %w", err)
	}

	resp, err := p.client.Post(pagerDutyEventURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("pagerduty: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("pagerduty: unexpected status code %d", resp.StatusCode)
	}
	return nil
}
