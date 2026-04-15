package notify

import (
	"context"
	"time"
)

// Alert represents a vault secret expiry alert passed to notifiers.
type Alert struct {
	SecretPath string
	Message    string
	Severity   string
	ExpiresAt  time.Time
}

// Notifier is the common interface implemented by all notification backends.
type Notifier interface {
	Send(ctx context.Context, alert Alert) error
}

// MultiNotifier fans out an alert to multiple Notifier implementations.
type MultiNotifier struct {
	notifiers []Notifier
}

// NewMultiNotifier creates a MultiNotifier wrapping the provided notifiers.
func NewMultiNotifier(notifiers ...Notifier) *MultiNotifier {
	return &MultiNotifier{notifiers: notifiers}
}

// Send sends the alert to all registered notifiers, collecting any errors.
func (m *MultiNotifier) Send(ctx context.Context, alert Alert) error {
	var errs []error
	for _, n := range m.notifiers {
		if err := n.Send(ctx, alert); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return &MultiNotifyError{Errors: errs}
	}
	return nil
}

// MultiNotifyError aggregates errors from multiple notifiers.
type MultiNotifyError struct {
	Errors []error
}

func (e *MultiNotifyError) Error() string {
	msg := "multi-notifier errors:"
	for _, err := range e.Errors {
		msg += " [" + err.Error() + "]"
	}
	return msg
}
