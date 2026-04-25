package vault

import (
	"testing"
	"time"
)

func TestNewAppRoleAlerter_NilScanner(t *testing.T) {
	a := NewAppRoleAlerter(nil, nil)
	if a != nil {
		t.Fatal("expected nil alerter for nil scanner")
	}
}

func TestNewAppRoleAlerter_DefaultThresholds(t *testing.T) {
	ts := newAppRoleTestServer(t)
	defer ts.Close()

	client, _ := NewClient(ts.URL, "test-token")
	scanner := NewAppRoleScanner(client, "approle")
	alerter := NewAppRoleAlerter(scanner, nil)

	if alerter == nil {
		t.Fatal("expected non-nil alerter")
	}
	if len(alerter.thresholds) == 0 {
		t.Fatal("expected default thresholds to be set")
	}
}

func TestAppRoleAlerter_Evaluate_CriticalAlert(t *testing.T) {
	ts := newAppRoleTestServer(t)
	defer ts.Close()

	client, _ := NewClient(ts.URL, "test-token")
	scanner := NewAppRoleScanner(client, "approle")

	thresholds := []AppRoleThreshold{
		{MaxTTL: 24 * time.Hour, Severity: SeverityCritical},
	}
	alerter := NewAppRoleAlerter(scanner, thresholds)

	role := AppRoleInfo{
		Name:   "my-role",
		MaxTTL: 1 * time.Hour,
	}

	alerts := alerter.EvaluateRole(role)
	if len(alerts) == 0 {
		t.Fatal("expected at least one alert")
	}
	if alerts[0].Severity != SeverityCritical {
		t.Errorf("expected critical, got %s", alerts[0].Severity)
	}
}

func TestAppRoleAlerter_Evaluate_NoAlert(t *testing.T) {
	ts := newAppRoleTestServer(t)
	defer ts.Close()

	client, _ := NewClient(ts.URL, "test-token")
	scanner := NewAppRoleScanner(client, "approle")

	thresholds := []AppRoleThreshold{
		{MaxTTL: 1 * time.Hour, Severity: SeverityCritical},
	}
	alerter := NewAppRoleAlerter(scanner, thresholds)

	role := AppRoleInfo{
		Name:   "long-lived-role",
		MaxTTL: 720 * time.Hour,
	}

	alerts := alerter.EvaluateRole(role)
	if len(alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(alerts))
	}
}
