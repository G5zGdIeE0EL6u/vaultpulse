package vault

import (
	"context"
	"fmt"
)

// AgentAlert holds alert information about a Vault Agent.
type AgentAlert struct {
	Message  string
	Severity string
}

// AgentAlerter evaluates AgentStatus and produces alerts.
type AgentAlerter struct {
	checker *AgentChecker
}

// NewAgentAlerter returns a new AgentAlerter or error if checker is nil.
func NewAgentAlerter(c *AgentChecker) (*AgentAlerter, error) {
	if c == nil {
		return nil, fmt.Errorf("vault: agent checker must not be nil")
	}
	return &AgentAlerter{checker: c}, nil
}

// Evaluate fetches agent status and returns any alerts.
func (a *AgentAlerter) Evaluate(ctx context.Context) ([]AgentAlert, error) {
	status, err := a.checker.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("agent alerter: %w", err)
	}

	var alerts []AgentAlert

	if !status.Running {
		alerts = append(alerts, AgentAlert{
			Message:  "Vault Agent is not running",
			Severity: "critical",
		})
		return alerts, nil
	}

	if !status.AutoAuthOK {
		alerts = append(alerts, AgentAlert{
			Message:  "Vault Agent auto-auth is failing",
			Severity: "warning",
		})
	}

	return alerts, nil
}
