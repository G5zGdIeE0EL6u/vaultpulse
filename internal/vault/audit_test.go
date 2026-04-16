package vault

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestNewAuditLogger_DefaultsToStdout(t *testing.T) {
	l := NewAuditLogger(nil)
	if l == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestAuditLogger_Log_Success(t *testing.T) {
	var buf bytes.Buffer
	l := NewAuditLogger(&buf)

	err := l.Log(AuditEntry{
		Timestamp: time.Now().UTC(),
		Path:      "secret/db",
		Action:    "renew",
		Severity:  "warning",
		Message:   "lease renewed",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "secret/db") {
		t.Errorf("expected path in output, got: %s", out)
	}
	if !strings.Contains(out, "renew") {
		t.Errorf("expected action in output, got: %s", out)
	}
}

func TestAuditLogger_Log_EmptyPath(t *testing.T) {
	var buf bytes.Buffer
	l := NewAuditLogger(&buf)
	err := l.Log(AuditEntry{Action: "renew"})
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestAuditLogger_Log_EmptyAction(t *testing.T) {
	var buf bytes.Buffer
	l := NewAuditLogger(&buf)
	err := l.Log(AuditEntry{Path: "secret/db"})
	if err == nil {
		t.Fatal("expected error for empty action")
	}
}

func TestAuditLogger_Log_ZeroTimestampFilled(t *testing.T) {
	var buf bytes.Buffer
	l := NewAuditLogger(&buf)
	err := l.Log(AuditEntry{Path: "secret/x", Action: "scan"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected non-empty output")
	}
}

func TestAuditLogger_LogAlert(t *testing.T) {
	var buf bytes.Buffer
	l := NewAuditLogger(&buf)

	alert := Alert{
		Path:     "secret/api",
		Severity: SeverityCritical,
		Message:  "expiring soon",
	}
	err := l.LogAlert("alert", alert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "secret/api") {
		t.Errorf("expected path in output, got: %s", out)
	}
	if !strings.Contains(out, "critical") {
		t.Errorf("expected severity in output, got: %s", out)
	}
}
