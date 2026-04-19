package vault

import (
	"fmt"
	"time"
)

// GitHubRole represents a GitHub auth backend role/team mapping.
type GitHubRole struct {
	Team      string
	Policies  []string
	TTL       time.Duration
	MaxTTL    time.Duration
	CreatedAt time.Time
}

// IsExpired returns true if the role's TTL has elapsed.
func (g *GitHubRole) IsExpired() bool {
	if g.TTL <= 0 {
		return false
	}
	return time.Since(g.CreatedAt) >= g.TTL
}

// TimeUntilExpiry returns the duration until the role expires.
func (g *GitHubRole) TimeUntilExpiry() time.Duration {
	if g.TTL <= 0 {
		return 0
	}
	return g.TTL - time.Since(g.CreatedAt)
}

// GitHubScanner scans GitHub auth backend roles.
type GitHubScanner struct {
	client *Client
	mount  string
}

// NewGitHubScanner creates a new GitHubScanner. Returns nil if client is nil.
func NewGitHubScanner(client *Client, mount string) *GitHubScanner {
	if client == nil {
		return nil
	}
	if mount == "" {
		mount = "github"
	}
	return &GitHubScanner{client: client, mount: mount}
}

// ListTeams returns all team names configured in the GitHub auth backend.
func (s *GitHubScanner) ListTeams() ([]string, error) {
	path := fmt.Sprintf("/v1/auth/%s/map/teams", s.mount)
	data, err := s.client.List(path)
	if err != nil {
		return nil, fmt.Errorf("github: list teams: %w", err)
	}
	keys, _ := data["keys"].([]interface{})
	teams := make([]string, 0, len(keys))
	for _, k := range keys {
		if t, ok := k.(string); ok {
			teams = append(teams, t)
		}
	}
	return teams, nil
}

// GetTeam returns the GitHubRole for a given team name.
func (s *GitHubScanner) GetTeam(team string) (*GitHubRole, error) {
	if team == "" {
		return nil, fmt.Errorf("github: team name must not be empty")
	}
	path := fmt.Sprintf("/v1/auth/%s/map/teams/%s", s.mount, team)
	data, err := s.client.Read(path)
	if err != nil {
		return nil, fmt.Errorf("github: get team %q: %w", team, err)
	}
	role := &GitHubRole{
		Team:      team,
		CreatedAt: time.Now(),
	}
	if v, ok := data["value"].(string); ok {
		role.Policies = []string{v}
	}
	if ttl, ok := data["ttl"].(float64); ok {
		role.TTL = time.Duration(ttl) * time.Second
	}
	if max, ok := data["max_ttl"].(float64); ok {
		role.MaxTTL = time.Duration(max) * time.Second
	}
	return role, nil
}
