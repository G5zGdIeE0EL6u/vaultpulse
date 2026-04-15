package notify

import (
	"fmt"
	"net/smtp"
	"strings"
	"time"

	"github.com/user/vaultpulse/internal/vault"
)

// EmailNotifier sends alert notifications via SMTP.
type EmailNotifier struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	To       []string
	Timeout  time.Duration
}

// EmailConfig holds configuration for the email notifier.
type EmailConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	To       []string
	Timeout  time.Duration
}

// NewEmailNotifier creates a new EmailNotifier with the given config.
// If Timeout is zero, it defaults to 10 seconds.
func NewEmailNotifier(cfg EmailConfig) *EmailNotifier {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Port == 0 {
		cfg.Port = 587
	}
	return &EmailNotifier{
		Host:     cfg.Host,
		Port:     cfg.Port,
		Username: cfg.Username,
		Password: cfg.Password,
		From:     cfg.From,
		To:       cfg.To,
		Timeout:  cfg.Timeout,
	}
}

// Send delivers an alert notification via email.
func (e *EmailNotifier) Send(alert vault.Alert) error {
	if e.Host == "" {
		return fmt.Errorf("email notifier: SMTP host is required")
	}
	if len(e.To) == 0 {
		return fmt.Errorf("email notifier: at least one recipient is required")
	}

	subject := fmt.Sprintf("[VaultPulse][%s] Secret expiry alert: %s", alert.Severity, alert.Path)
	body := fmt.Sprintf(
		"Secret: %s\nSeverity: %s\nExpires At: %s\nTime Until Expiry: %s\n",
		alert.Path,
		alert.Severity,
		alert.ExpiresAt.Format(time.RFC3339),
		alert.TimeUntilExpiry().Round(time.Second),
	)

	msg := fmt.Sprintf(
		"From: %s\nTo: %s\r\nSubject: %s\r\n\r\n%s",
		e.From,
		strings.Join(e.To, ", "),
		subject,
		body,
	)

	addr := fmt.Sprintf("%s:%d", e.Host, e.Port)
	auth := smtp.PlainAuth("", e.Username, e.Password, e.Host)

	if err := smtp.SendMail(addr, auth, e.From, e.To, []byte(msg)); err != nil {
		return fmt.Errorf("email notifier: failed to send email: %w", err)
	}
	return nil
}
