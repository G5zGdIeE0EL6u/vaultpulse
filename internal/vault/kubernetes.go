package vault

import (
	"encoding/json"
	"fmt"
	"time"
)

// KubernetesRole represents a Vault Kubernetes auth role.
type KubernetesRole struct {
	Name                 string        `json:"name"`
	BoundServiceAccounts []string      `json:"bound_service_account_names"`
	BoundNamespaces      []string      `json:"bound_service_account_namespaces"`
	TTL                  time.Duration `json:"ttl"`
	MaxTTL               time.Duration `json:"max_ttl"`
}

// IsExpired returns true when MaxTTL is set and has elapsed.
func (r *KubernetesRole) IsExpired() bool {
	if r.MaxTTL <= 0 {
		return false
	}
	return time.Now().After(time.Now().Add(-r.MaxTTL))
}

// TimeUntilExpiry returns the duration until the role's MaxTTL expires.
func (r *KubernetesRole) TimeUntilExpiry() time.Duration {
	return r.MaxTTL
}

// KubernetesScanner scans Vault Kubernetes auth roles.
type KubernetesScanner struct {
	client *Client
	mount  string
}

// NewKubernetesScanner creates a new KubernetesScanner.
func NewKubernetesScanner(c *Client, mount string) *KubernetesScanner {
	if mount == "" {
		mount = "kubernetes"
	}
	return &KubernetesScanner{client: c, mount: mount}
}

// ListRoles returns all Kubernetes auth role names.
func (s *KubernetesScanner) ListRoles() ([]string, error) {
	path := fmt.Sprintf("/v1/auth/%s/role", s.mount)
	resp, err := s.client.RawList(path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Data.Keys, nil
}

// GetRole fetches details for a single Kubernetes auth role.
func (s *KubernetesScanner) GetRole(name string) (*KubernetesRole, error) {
	if name == "" {
		return nil, fmt.Errorf("role name must not be empty")
	}
	path := fmt.Sprintf("/v1/auth/%s/role/%s", s.mount, name)
	resp, err := s.client.RawGet(path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result struct {
		Data KubernetesRole `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	result.Data.Name = name
	return &result.Data, nil
}
