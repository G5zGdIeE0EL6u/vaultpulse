package vault

import (
	"fmt"
	"log"
	"time"
)

// MonitorConfig holds configuration for the secret monitor.
type MonitorConfig struct {
	Paths           []string
	PollInterval    time.Duration
	WarningThreshold time.Duration
}

// Monitor polls Vault secrets and emits alerts when expiry is near.
type Monitor struct {
	client *Client
	cfg    MonitorConfig
	alerts chan Alert
}

// NewMonitor creates a Monitor for the given client and config.
func NewMonitor(client *Client, cfg MonitorConfig) *Monitor {
	return &Monitor{
		client: client,
		cfg:    cfg,
		alerts: make(chan Alert, 64),
	}
}

// Alerts returns a read-only channel of alert events.
func (m *Monitor) Alerts() <-chan Alert {
	return m.alerts
}

// Run starts the polling loop. It blocks until ctx-like stop is called or an unrecoverable error occurs.
func (m *Monitor) Run(stop <-chan struct{}) error {
	ticker := time.NewTicker(m.cfg.PollInterval)
	defer ticker.Stop()

	log.Printf("monitor: starting, polling %d path(s) every %s", len(m.cfg.Paths), m.cfg.PollInterval)

	for {
		select {
		case <-stop:
			log.Println("monitor: stopping")
			close(m.alerts)
			return nil
		case <-ticker.C:
			if err := m.poll(); err != nil {
				log.Printf("monitor: poll error: %v", err)
			}
		}
	}
}

func (m *Monitor) poll() error {
	for _, path := range m.cfg.Paths {
		info, err := m.client.ReadSecret(path)
		if err != nil {
			return fmt.Errorf("poll %q: %w", path, err)
		}
		if info.ExpiresAt == nil {
			continue
		}
		untilExpiry := time.Until(*info.ExpiresAt)
		if untilExpiry <= m.cfg.WarningThreshold {
			m.alerts <- Alert{
				Path:      path,
				ExpiresAt: *info.ExpiresAt,
				TTL:       info.TTL,
				LeaseID:   info.LeaseID,
				Severity:  severityFromTTL(untilExpiry),
			}
		}
	}
	return nil
}

func severityFromTTL(remaining time.Duration) Severity {
	if remaining <= 5*time.Minute {
		return SeverityCritical
	}
	return SeverityWarning
}
