package vault

import (
	"context"
	"fmt"
	"strings"
)

// NamespaceInfo holds metadata about a Vault namespace.
type NamespaceInfo struct {
	Path        string
	ID          string
	CustomMeta  map[string]string
}

// NamespaceLister lists child namespaces under a given path.
type NamespaceLister struct {
	client *Client
}

// NewNamespaceLister creates a new NamespaceLister.
func NewNamespaceLister(c *Client) *NamespaceLister {
	return &NamespaceLister{client: c}
}

// List returns all child namespaces under the given parent path.
// Pass an empty string to list top-level namespaces.
func (nl *NamespaceLister) List(ctx context.Context, parent string) ([]NamespaceInfo, error) {
	if nl.client == nil {
		return nil, fmt.Errorf("namespace lister: nil client")
	}

	path := "sys/namespaces"
	if parent != "" {
		parent = strings.Trim(parent, "/")
		path = fmt.Sprintf("%s/%s/sys/namespaces", parent, path)
	}

	secret, err := nl.client.vault.Logical().ListWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("namespace lister: list %q: %w", path, err)
	}
	if secret == nil || secret.Data == nil {
		return []NamespaceInfo{}, nil
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return []NamespaceInfo{}, nil
	}

	var namespaces []NamespaceInfo
	for _, k := range keys {
		name, ok := k.(string)
		if !ok {
			continue
		}
		namespaces = append(namespaces, NamespaceInfo{
			Path: strings.TrimSuffix(name, "/"),
		})
	}
	return namespaces, nil
}
