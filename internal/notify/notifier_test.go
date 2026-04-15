package notify

import (
	"context"
	"errors"
	"testing"
	"time"
)

type mockNotifier struct {
	sendErr error
	called  int
}

func (m *mockNotifier) Send(_ context.Context, _ Alert) error {
	m.called++
	return m.sendErr
}

func TestMultiNotifier_AllSuccess(t *testing.T) {
	a := &mockNotifier{}
	b := &mockNotifier{}
	mn := NewMultiNotifier(a, b)

	err := mn.Send(context.Background(), Alert{SecretPath: "secret/test", Severity: "info"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if a.called != 1 || b.called != 1 {
		t.Errorf("expected each notifier called once")
	}
}

func TestMultiNotifier_PartialFailure(t *testing.T) {
	a := &mockNotifier{sendErr: errors.New("notifier a failed")}
	b := &mockNotifier{}
	mn := NewMultiNotifier(a, b)

	err := mn.Send(context.Background(), Alert{SecretPath: "secret/test"})
	if err == nil {
		t.Error("expected error from partial failure")
	}
	if b.called != 1 {
		t.Error("expected second notifier to still be called")
	}
}

func TestMultiNotifier_AllFailure(t *testing.T) {
	a := &mockNotifier{sendErr: errors.New("err a")}
	b := &mockNotifier{sendErr: errors.New("err b")}
	mn := NewMultiNotifier(a, b)

	err := mn.Send(context.Background(), Alert{})
	var me *MultiNotifyError
	if !errors.As(err, &me) {
		t.Errorf("expected MultiNotifyError, got %T", err)
	}
	if len(me.Errors) != 2 {
		t.Errorf("expected 2 errors, got %d", len(me.Errors))
	}
}

func TestMultiNotifyError_Message(t *testing.T) {
	e := &MultiNotifyError{Errors: []error{errors.New("foo"), errors.New("bar")}}
	msg := e.Error()
	if msg == "" {
		t.Error("expected non-empty error message")
	}
}

func TestAlert_Fields(t *testing.T) {
	now := time.Now()
	a := Alert{
		SecretPath: "secret/myapp/db",
		Message:    "expires in 1h",
		Severity:   "warning",
		ExpiresAt:  now,
	}
	if a.SecretPath != "secret/myapp/db" {
		t.Errorf("unexpected SecretPath: %s", a.SecretPath)
	}
	if !a.ExpiresAt.Equal(now) {
		t.Errorf("unexpected ExpiresAt")
	}
}
