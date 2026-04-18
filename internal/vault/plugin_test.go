package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/vault/api"
)

func newPluginTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"keys": []string{"my-plugin", "other-plugin"},
			},
		})
	}))
}

func TestNewPluginScanner_NotNil(t *testing.T) {
	client, _ := api.NewClient(api.DefaultConfig())
	ps, err := NewPluginScanner(client)
	if err != nil || ps == nil {
		t.Fatal("expected non-nil scanner")
	}
}

func TestNewPluginScanner_NilClient(t *testing.T) {
	_, err := NewPluginScanner(nil)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestListPlugins_Success(t *testing.T) {
	srv := newPluginTestServer(t)
	defer srv.Close()
	cfg := api.DefaultConfig()
	cfg.Address = srv.URL
	client, _ := api.NewClient(cfg)
	ps, _ := NewPluginScanner(client)
	plugins, err := ps.ListPlugins(context.Background(), "secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plugins) != 2 {
		t.Fatalf("expected 2 plugins, got %d", len(plugins))
	}
}

func TestListPlugins_EmptyType(t *testing.T) {
	client, _ := api.NewClient(api.DefaultConfig())
	ps, _ := NewPluginScanner(client)
	_, err := ps.ListPlugins(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty type")
	}
}

func TestNewPluginAlerter_NotNil(t *testing.T) {
	client, _ := api.NewClient(api.DefaultConfig())
	ps, _ := NewPluginScanner(client)
	pa, err := NewPluginAlerter(ps, []string{"bad-plugin"})
	if err != nil || pa == nil {
		t.Fatal("expected non-nil alerter")
	}
}

func TestPluginAlerter_Evaluate_BlockedDetected(t *testing.T) {
	srv := newPluginTestServer(t)
	defer srv.Close()
	cfg := api.DefaultConfig()
	cfg.Address = srv.URL
	client, _ := api.NewClient(cfg)
	ps, _ := NewPluginScanner(client)
	pa, _ := NewPluginAlerter(ps, []string{"my-plugin"})
	alerts, err := pa.Evaluate(context.Background(), "secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Severity != "critical" {
		t.Errorf("expected critical severity")
	}
}
