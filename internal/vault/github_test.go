package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newGitHubTestServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/github/map/teams", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"keys": []string{"dev", "ops"}},
		})
	})
	mux.HandleFunc("/v1/auth/github/map/teams/dev", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"value":   "default",
				"ttl":     float64(3600),
				"max_ttl": float64(7200),
			},
		})
	})
	return httptest.NewServer(mux)
}

func TestNewGitHubScanner_NotNil(t *testing.T) {
	s := newGitHubTestServer()
	defer s.Close()
	client, _ := NewClient(s.URL, "test-token")
	scanner := NewGitHubScanner(client, "")
	if scanner == nil {
		t.Fatal("expected non-nil scanner")
	}
	if scanner.mount != "github" {
		t.Errorf("expected default mount 'github', got %q", scanner.mount)
	}
}

func TestNewGitHubScanner_NilClient(t *testing.T) {
	scanner := NewGitHubScanner(nil, "github")
	if scanner != nil {
		t.Fatal("expected nil scanner for nil client")
	}
}

func TestGitHubListTeams_Success(t *testing.T) {
	s := newGitHubTestServer()
	defer s.Close()
	client, _ := NewClient(s.URL, "test-token")
	scanner := NewGitHubScanner(client, "github")
	teams, err := scanner.ListTeams()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(teams) == 0 {
		t.Fatal("expected at least one team")
	}
}

func TestGitHubGetTeam_Success(t *testing.T) {
	s := newGitHubTestServer()
	defer s.Close()
	client, _ := NewClient(s.URL, "test-token")
	scanner := NewGitHubScanner(client, "github")
	role, err := scanner.GetTeam("dev")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if role.Team != "dev" {
		t.Errorf("expected team 'dev', got %q", role.Team)
	}
	if role.TTL != 3600*time.Second {
		t.Errorf("unexpected TTL: %v", role.TTL)
	}
}

func TestGitHubGetTeam_EmptyName(t *testing.T) {
	s := newGitHubTestServer()
	defer s.Close()
	client, _ := NewClient(s.URL, "test-token")
	scanner := NewGitHubScanner(client, "github")
	_, err := scanner.GetTeam("")
	if err == nil {
		t.Fatal("expected error for empty team name")
	}
}

func TestGitHubRole_IsExpired_False(t *testing.T) {
	role := &GitHubRole{TTL: time.Hour, CreatedAt: time.Now()}
	if role.IsExpired() {
		t.Error("expected role not to be expired")
	}
}
