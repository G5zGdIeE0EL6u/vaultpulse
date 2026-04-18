package vault

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/api"
)

// PluginInfo holds metadata about a registered Vault plugin.
type PluginInfo struct {
	Name    string
	Type    string
	Version string
	Builtin bool
}

// PluginScanner lists plugins registered in Vault.
type PluginScanner struct {
	client *api.Client
}

// NewPluginScanner returns a new PluginScanner or an error if client is nil.
func NewPluginScanner(client *api.Client) (*PluginScanner, error) {
	if client == nil {
		return nil, fmt.Errorf("vault client must not be nil")
	}
	return &PluginScanner{client: client}, nil
}

// ListPlugins returns all plugins of the given type (auth, secret, database).
func (p *PluginScanner) ListPlugins(ctx context.Context, pluginType string) ([]PluginInfo, error) {
	if pluginType == "" {
		return nil, fmt.Errorf("plugin type must not be empty")
	}
	path := fmt.Sprintf("sys/plugins/catalog/%s", pluginType)
	secret, err := p.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("listing plugins: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return []PluginInfo{}, nil
	}
	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return []PluginInfo{}, nil
	}
	plugins := make([]PluginInfo, 0, len(keys))
	for _, k := range keys {
		name, _ := k.(string)
		if name == "" {
			continue
		}
		plugins = append(plugins, PluginInfo{
			Name: name,
			Type: pluginType,
		})
	}
	return plugins, nil
}
