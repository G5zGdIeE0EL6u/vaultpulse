package vault

import (
	"context"
	"testing"
)

func TestNewRaftAlerter_NotNil(t *testing.T) {
	c, _ := NewClient("http://127.0.0.1:8200", "tok")
	rc, _ := NewRaftChecker(c)
	ra, err := NewRaftAlerter(rc)
	if err != nil || ra == nil {
		t.Fatal("expected non-nil RaftAlerter")
	}
}

func TestNewRaftAlerter_NilChecker(t *testing.T) {
	_, err := NewRaftAlerter(nil)
	if err == nil {
		t.Fatal("expected error for nil checker")
	}
}

func TestRaftAlerter_Evaluate_Healthy(t *testing.T) {
	peers := []RaftPeer{
		{NodeID: "n1", Leader: true, Voter: true},
		{NodeID: "n2", Voter: true},
		{NodeID: "n3", Voter: true},
	}
	srv := newRaftTestServer(t, peers)
	defer srv.Close()

	c, _ := NewClient(srv.URL, "tok")
	rc, _ := NewRaftChecker(c)
	ra, _ := NewRaftAlerter(rc)
	alerts, err := ra.Evaluate(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Fatalf("expected no alerts, got %d", len(alerts))
	}
}

func TestRaftAlerter_Evaluate_NoLeader(t *testing.T) {
	peers := []RaftPeer{
		{NodeID: "n1", Leader: false, Voter: true},
		{NodeID: "n2", Leader: false, Voter: true},
	}
	srv := newRaftTestServer(t, peers)
	defer srv.Close()

	c, _ := NewClient(srv.URL, "tok")
	rc, _ := NewRaftChecker(c)
	ra, _ := NewRaftAlerter(rc)
	alerts, err := ra.Evaluate(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) == 0 {
		t.Fatal("expected at least one alert for no leader")
	}
	if alerts[0].Severity != SeverityCritical {
		t.Errorf("expected critical severity, got %s", alerts[0].Severity)
	}
}

func TestRaftAlerter_Evaluate_EvenVoters(t *testing.T) {
	peers := []RaftPeer{
		{NodeID: "n1", Leader: true, Voter: true},
		{NodeID: "n2", Voter: true},
	}
	srv := newRaftTestServer(t, peers)
	defer srv.Close()

	c, _ := NewClient(srv.URL, "tok")
	rc, _ := NewRaftChecker(c)
	ra, _ := NewRaftAlerter(rc)
	alerts, _ := ra.Evaluate(context.Background())
	found := false
	for _, a := range alerts {
		if a.Severity == SeverityWarning {
			found = true
		}
	}
	if !found {
		t.Fatal("expected warning alert for even voter count")
	}
}
