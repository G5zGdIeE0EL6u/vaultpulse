package vault_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewReplicationAlerter_NotNil(t *testing.T) {
	a := NewReplicationAlerter()
	require.NotNil(t, a)
}

func TestReplicationAlerter_Evaluate_Healthy(t *testing.T) {
	a := NewReplicationAlerter()
	status := &ReplicationStatus{
		DRMode:          "primary",
		DRState:         "running",
		PerfMode:        "primary",
		PerfState:       "running",
	}
	alerts := a.Evaluate(status)
	assert.Empty(t, alerts)
}

func TestReplicationAlerter_Evaluate_DRDegraded(t *testing.T) {
	a := NewReplicationAlerter()
	status := &ReplicationStatus{
		DRMode:    "primary",
		DRState:   "idle",
		PerfMode:  "disabled",
		PerfState: "",
	}
	alerts := a.Evaluate(status)
	require.Len(t, alerts, 1)
	assert.Equal(t, "warning", alerts[0].Severity)
	assert.Contains(t, alerts[0].Message, "DR")
}

func TestReplicationAlerter_Evaluate_PerfDegraded(t *testing.T) {
	a := NewReplicationAlerter()
	status := &ReplicationStatus{
		DRMode:    "disabled",
		DRState:   "",
		PerfMode:  "primary",
		PerfState: "idle",
	}
	alerts := a.Evaluate(status)
	require.Len(t, alerts, 1)
	assert.Equal(t, "warning", alerts[0].Severity)
	assert.Contains(t, alerts[0].Message, "performance")
}

func TestReplicationAlerter_Evaluate_NilStatus(t *testing.T) {
	a := NewReplicationAlerter()
	alerts := a.Evaluate(nil)
	assert.Empty(t, alerts)
}
