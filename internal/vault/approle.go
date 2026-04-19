package vault

import (
	"encoding/json"
	"fmt"
	"time"
)

// AppRoleInfo holds metadata about a Vault AppRole.
type AppRoleInfo struct {
	RoleID        string        `json:"role_id"`
	SecretIDTTL   time.Duration `json:"secret_id_ttl"`
	TokenTTL      time.Duration `json:"token_ttl"`
	TokenMaxTTL   time.Duration `json:"token_max_ttl"`
	BindSecretID  bool          `json:"bind_secret_id"`
}

// AppRoleScanner lists and fetches AppRole metadata from Vault.
type AppRoleScanner struct {
	client *Client
	mount  string
}

// NewAppRoleScanner creates a new AppRoleScanner. Defaults mount to "auth/approle".
func NewAppRoleScanner(c *Client, mount string) (*AppRoleScanner, error) {
	if c == nil {
		return nil, fmt.Errorf("approle: client must not be nil")
	}
	if mount == "" {
		mount = "auth/approle"
	}
	return &AppRoleScanner{client: c, mount: mount}, nil
}

// ListRoles returns all AppRole role names under the configured mount.
func (s *AppRoleScanner) ListRoles() ([]string, error) {
	path := fmt.Sprintf("%s/role", s.mount)
	resp, err := s.client.RawList(path)
	if err != nil {
		return nil, fmt.Errorf("approle: list roles: %w", err)
	}
	keys, ok := resp["keys"].([]interface{})
	if !ok {
		return nil, nil
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if s, ok := k.(string); ok {
			out = append(out, s)
		}
	}
	return out, nil
}

// GetRole fetches AppRoleInfo for a named role.
func (s *AppRoleScanner) GetRole(name string) (*AppRoleInfo, error) {
	if name == "" {
		return nil, fmt.Errorf("approle: role name must not be empty")
	}
	path := fmt.Sprintf("%s/role/%s", s.mount, name)
	resp, err := s.client.RawRead(path)
	if err != nil {
		return nil, fmt.Errorf("approle: get role %q: %w", name, err)
	}
	b, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}
	var info AppRoleInfo
	if err := json.Unmarshal(b, &info); err != nil {
		return nil, err
	}
	return &info, nil
}
