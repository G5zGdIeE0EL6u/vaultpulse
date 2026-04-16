package vault

import (
	"testing"
	"time"
)

func TestDefaultTokenAlertThresholds_NotEmpty(t *testing.T) {
	thresholds := DefaultTokenAlertThresholds()
	if len(thresholds) == 0 {
		t.Fatal("expected non-empty default thresholds")
	}
}

func TestNewTokenAlerter_NotNil(t *testing.T) {
	ta := NewTokenAlerter(DefaultTokenAlertThresholds())
	if ta == nil {
		t.Fatal("expected non-nil TokenAlerter")
	}
}

func TestTokenAlerter_Evaluate_NoAlert(t *testing.T) {
	ta := NewTokenAlerter(DefaultTokenAlertThresholds())
	info := &TokenInfo{
		ExpireTime: time.Now().Add(48 * time.Hour),
		Renewable:  true,
	}
	alerts := ta.Evaluate(info)
	if len(alerts) != 0 {
		t.Fatalf("expected no alerts, got %d", len(alerts))
	}
}

func TestTokenAlerter_Evaluate_CriticalAlert(t *testing.T) {
	ta := NewTokenAlerter(DefaultTokenAlertThresholds())
	info := &TokenInfo{
		ExpireTime: time.Now().Add(30 * time.Minute),
		Renewable:  false,
	}
	alerts := ta.Evaluate(info)
	if len(alerts) == 0 {
		t.Fatal("expected at least one alert")
	}
	found := false
	for _, a := range alerts {
		if a.Severity == SeverityCritical {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected a critical severity alert")
	}
}

func TestTokenAlerter_Evaluate_WarningAlert(t *testing.T) {
	ta := NewTokenAlerter(DefaultTokenAlertThresholds())
	info := &TokenInfo{
		ExpireTime: time.Now().Add(6 * time.Hour),
		Renewable:  true,
	}
	alerts := ta.Evaluate(info)
	if len(alerts) == 0 {
		t.Fatal("expected at least one alert")
	}
}

func TestTokenAlerter_Evaluate_ExpiredToken(t *testing.T) {
	ta := NewTokenAlerter(DefaultTokenAlertThresholds())
	info := &TokenInfo{
		ExpireTime: time.Now().Add(-1 * time.Minute),
		Renewable:  false,
	}
	alerts := ta.Evaluate(info)
	if len(alerts) == 0 {
		t.Fatal("expected alerts for expired token")
	}
}
