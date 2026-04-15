package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// SlackNotifier sends alert notifications to a Slack webhook URL.
type SlackNotifier struct {
	webhookURL string
	client     *http.Client
}

type slackPayload struct {
	Text        string       `json:"text"`
	Attachments []slackAttachment `json:"attachments,omitempty"`
}

type slackAttachment struct {
	Color  string `json:"color"`
	Text   string `json:"text"`
	Footer string `json:"footer"`
}

// NewSlackNotifier creates a new SlackNotifier with the given webhook URL.
func NewSlackNotifier(webhookURL string, timeout time.Duration) *SlackNotifier {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &SlackNotifier{
		webhookURL: webhookURL,
		client:     &http.Client{Timeout: timeout},
	}
}

// Send dispatches a Slack message for the given alert message and severity.
func (s *SlackNotifier) Send(message, severity string) error {
	if s.webhookURL == "" {
		return fmt.Errorf("slack webhook URL is empty")
	}

	color := colorForSeverity(severity)

	payload := slackPayload{
		Text: fmt.Sprintf(":rotating_light: *VaultPulse Alert* [%s]", severity),
		Attachments: []slackAttachment{
			{
				Color:  color,
				Text:   message,
				Footer: "vaultpulse",
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal slack payload: %w", err)
	}

	resp, err := s.client.Post(s.webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("slack request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("slack returned non-2xx status: %d", resp.StatusCode)
	}
	return nil
}

func colorForSeverity(severity string) string {
	switch severity {
	case "critical":
		return "#FF0000"
	case "warning":
		return "#FFA500"
	default:
		return "#36a64f"
	}
}
