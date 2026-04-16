package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// KVSecret represents a KV v2 secret with metadata.
type KVSecret struct {
	Path      string
	Data      map[string]interface{}
	CreatedAt time.Time
	Version   int
}

// KVReader reads KV v2 secrets from Vault.
type KVReader struct {
	client *Client
	mount  string
}

// NewKVReader creates a KVReader for the given KV v2 mount.
func NewKVReader(client *Client, mount string) *KVReader {
	if mount == "" {
		mount = "secret"
	}
	return &KVReader{client: client, mount: mount}
}

// Read fetches a KV v2 secret at the given path.
func (r *KVReader) Read(path string) (*KVSecret, error) {
	if path == "" {
		return nil, fmt.Errorf("kv: path must not be empty")
	}

	url := fmt.Sprintf("%s/v1/%s/data/%s", r.client.address, r.mount, path)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("kv: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", r.client.token)

	resp, err := r.client.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kv: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("kv: secret not found at path %q", path)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kv: unexpected status %d", resp.StatusCode)
	}

	var body struct {
		Data struct {
			Data     map[string]interface{} `json:"data"`
			Metadata struct {
				CreatedTime string `json:"created_time"`
				Version     int    `json:"version"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("kv: decode response: %w", err)
	}

	createdAt, _ := time.Parse(time.RFC3339Nano, body.Data.Metadata.CreatedTime)
	return &KVSecret{
		Path:      path,
		Data:      body.Data.Data,
		CreatedAt: createdAt,
		Version:   body.Data.Metadata.Version,
	}, nil
}
