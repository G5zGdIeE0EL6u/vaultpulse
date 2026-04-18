package vault

import (
	"context"
	"fmt"
)

// PluginAlerter raises alerts for plugins matching a blocklist.
type PluginAlerter struct {
	scanner   *PluginScanner
	blocklist map[string]struct{}
}

// NewPluginAlerter creates a PluginAlerter with the given blocked plugin names.
func NewPluginAlerter(scanner *PluginScanner, blocked []string) (*PluginAlerter, error) {
	if scanner == nil {
		return nil, fmt.Errorf("plugin scanner must not be nil")
	}
	bm := make(map[string]struct{}, len(blocked))
	for _, b := range blocked {
		bm[b] = struct{}{}
	}
	return &PluginAlerter{scanner: scanner, blocklist: bm}, nil
}

// PluginAlert represents a detected blocked plugin.
type PluginAlert struct {
	Plugin   PluginInfo
	Message  string
	Severity string
}

// Evaluate scans plugins of the given type and returns alerts for blocked ones.
func (pa *PluginAlerter) Evaluate(ctx context.Context, pluginType string) ([]PluginAlert, error) {
	plugins, err := pa.scanner.ListPlugins(ctx, pluginType)
	if err != nil {
		return nil, err
	}
	var alerts []PluginAlert
	for _, p := range plugins {
		if _, blocked := pa.blocklist[p.Name]; blocked {
			alerts = append(alerts, PluginAlert{
				Plugin:   p,
				Message:  fmt.Sprintf("blocked plugin detected: %s (%s)", p.Name, p.Type),
				Severity: "critical",
			})
		}
	}
	return alerts, nil
}
