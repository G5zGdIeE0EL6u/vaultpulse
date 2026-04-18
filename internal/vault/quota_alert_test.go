package vault

import (
	"testing"
)

func TestNewQuotaAlerter_NotNil(t *testing.T) {
	srv := newQuotaTestServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "token")
	qc, _ := NewQuotaChecker(c)
	qa, err := NewQuotaAlerter(qc)
	if err != nil || qa == nil {
		t.Fatal("expected non-nil QuotaAlerter")
	}
}

func TestNewQuotaAlerter_NilChecker(t *testing.T) {
	_, err := NewQuotaAlerter(nil)
	if err == nil {
		t.Fatal("expected error for nil checker")
	}
}

func TestNewQuotaAlerter_DefaultThresholds(t *testing.T) {
	srv := newQuotaTestServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "token")
	qc, _ := NewQuotaChecker(c)
	qa, _ := NewQuotaAlerter(qc)
	if qa.WarnThreshold != 50.0 {
		t.Errorf("expected WarnThreshold 50, got %f", qa.WarnThreshold)
	}
	if qa.CritThreshold != 10.0 {
		t.Errorf("expected CritThreshold 10, got %f", qa.CritThreshold)
	}
}

func TestQuotaAlerter_Evaluate_RaisesAlert(t *testing.T) {
	srv := newQuotaTestServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "token")
	qc, _ := NewQuotaChecker(c)
	qa, _ := NewQuotaAlerter(qc)
	alerts, err := qa.Evaluate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// kv-limit has rate=5, below CritThreshold=10 → critical alert
	if len(alerts) == 0 {
		t.Fatal("expected at least one alert")
	}
	var found bool
	for _, a := range alerts {
		if a.QuotaName == "kv-limit" && a.Severity == "critical" {
			found = true
		}
	}
	if !found {
		t.Error("expected critical alert for kv-limit")
	}
}

func TestQuotaAlerter_Evaluate_NoAlertForHighRate(t *testing.T) {
	srv := newQuotaTestServer(t)
	defer srv.Close()
	c, _ := NewClient(srv.URL, "token")
	qc, _ := NewQuotaChecker(c)
	qa, _ := NewQuotaAlerter(qc)
	alerts, _ := qa.Evaluate()
	for _, a := range alerts {
		if a.QuotaName == "global" {
			t.Error("did not expect alert for global quota with rate=100")
		}
	}
}
