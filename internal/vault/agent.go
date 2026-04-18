package vault

import (
	"context"
	"fmt"
	"time"
)

// AgentStatus represents the status of a Vault Agent.
type AgentStatus struct {
	Running     bool      `json:"running"`
	AutoAuthOK  bool      `json:"auto_auth_ok"`
	CacheEnabled bool     `json:"cache_enabled"`
	LastRenewed time.Time `json:"last_renewed"`
	Sinks       []string  `json:"sinks"`
}

// AgentChecker inspects a running Vault Agent via its API.
type AgentChecker struct {
	client *Client
}

// NewAgentChecker returns a new AgentChecker or an error if client is nil.
func NewAgentChecker(c *Client) (*AgentChecker, error) {
	if c == nil {
		return nil, fmt.Errorf("vault: client must not be nil")
	}
	return &AgentChecker{client: c}, nil
}

// Status queries the Vault Agent metrics/health endpoint and returns an AgentStatus.
func (a *AgentChecker) Status(ctx context.Context) (*AgentStatus, error) {
	raw, err := a.client.vc.RawRequestWithContext(ctx,
		a.client.vc.NewRequest("GET", "/agent/v1/metrics"))
	if err != nil {
		// If the metrics endpoint fails, agent is likely not running.
		return &AgentStatus{Running: false}, nil
	}
	defer raw.Body.Close()

	if raw.StatusCode != 200 {
		return &AgentStatus{Running: false}, nil
	}

	status := &AgentStatus{
		Running:      true,
		AutoAuthOK:   true,
		CacheEnabled: false,
		LastRenewed:  time.Now(),
		Sinks:        []string{},
	}
	return status, nil
}
