package notify

import (
	"net"
	"net/smtp"
	"testing"
	"time"

	"pulse/internal/vault"
)

func TestNewEmailNotifier_Defaults(t *testing.T) {
	notifier := NewEmailNotifier(EmailConfig{
		Host: "smtp.example.com",
		From: "vault@example.com",
		To:   []string{"admin@example.com"},
	})

	if notifier.Timeout != 10*time.Second {
		t.Errorf("expected default timeout 10s, got %v", notifier.Timeout)
	}
	if notifier.Port != 587 {
		t.Errorf("expected default port 587, got %d", notifier.Port)
	}
}

func TestNewEmailNotifier_CustomValues(t *testing.T) {
	cfg := EmailConfig{
		Host:    "smtp.custom.com",
		Port:    465,
		Timeout: 5 * time.Second,
		From:    "from@custom.com",
		To:      []string{"to@custom.com"},
	}
	notifier := NewEmailNotifier(cfg)

	if notifier.Port != 465 {
		t.Errorf("expected port 465, got %d", notifier.Port)
	}
	if notifier.Timeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %v", notifier.Timeout)
	}
}

func TestSendEmail_EmptyHost(t *testing.T) {
	notifier := NewEmailNotifier(EmailConfig{
		To: []string{"admin@example.com"},
	})
	alert := vault.Alert{
		Path:      "secret/test",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Severity:  vault.SeverityWarning,
	}
	err := notifier.Send(alert)
	if err == nil {
		t.Fatal("expected error for empty host, got nil")
	}
}

func TestSendEmail_NoRecipients(t *testing.T) {
	notifier := NewEmailNotifier(EmailConfig{
		Host: "smtp.example.com",
		From: "vault@example.com",
	})
	alert := vault.Alert{
		Path:      "secret/test",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Severity:  vault.SeverityWarning,
	}
	err := notifier.Send(alert)
	if err == nil {
		t.Fatal("expected error for no recipients, got nil")
	}
}

func TestSendEmail_SMTPFailure(t *testing.T) {
	// Start a that immediately closes connections to simulate failure.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	_ = smtp.PlainAuth // ensure import used
	addr := ln.Addr().(*net.TCPAddr)
	notifier := NewEmailNotifier(EmailConfig{
		Host: "127.0.0.1",
		Port: addr.Port,
		From: "vault@example.com",
		To:   []string{"admin@example.com"},
	})
	alert := vault.Alert{
		Path:      "secret/db",
		ExpiresAt: time.Now().Add(30 * time.Minute),
		Severity:  vault.SeverityCritical,
	}
	err = notifier.Send(alert)
	if err == nil {
		t.Fatal( SMTP error, got nil")
	}
}
