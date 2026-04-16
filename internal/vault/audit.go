package vault

import (
	"fmt"
	"io"
	"os"
	"time"
)

// AuditEntry records a single audit event for a secret or lease action.
type AuditEntry struct {
	Timestamp time.Time
	Path      string
	Action    string
	Severity  string
	Message   string
}

// AuditLogger writes audit entries to a destination writer.
type AuditLogger struct {
	out io.Writer
}

// NewAuditLogger creates an AuditLogger writing to the given writer.
// If w is nil, os.Stdout is used.
func NewAuditLogger(w io.Writer) *AuditLogger {
	if w == nil {
		w = os.Stdout
	}
	return &AuditLogger{out: w}
}

// Log writes a formatted audit entry.
func (a *AuditLogger) Log(entry AuditEntry) error {
	if entry.Path == "" {
		return fmt.Errorf("audit: path must not be empty")
	}
	if entry.Action == "" {
		return fmt.Errorf("audit: action must not be empty")
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	_, err := fmt.Fprintf(
		a.out,
		"%s | action=%-10s | severity=%-8s | path=%s | %s\n",
		entry.Timestamp.Format(time.RFC3339),
		entry.Action,
		entry.Severity,
		entry.Path,
		entry.Message,
	)
	return err
}

// LogAlert is a convenience wrapper that logs an Alert as an audit entry.
func (a *AuditLogger) LogAlert(action string, alert Alert) error {
	return a.Log(AuditEntry{
		Timestamp: time.Now().UTC(),
		Path:      alert.Path,
		Action:    action,
		Severity:  string(alert.Severity),
		Message:   alert.Message,
	})
}
