package vault

import (
	"fmt"
	"time"
)

// CertInfo holds metadata about a PKI certificate managed by Vault.
type CertInfo struct {
	Serial      string
	CommonName  string
	Expiry      time.Time
	Revoked     bool
}

// IsExpired returns true if the certificate has passed its expiry time.
func (c *CertInfo) IsExpired() bool {
	return time.Now().After(c.Expiry)
}

// TimeUntilExpiry returns the duration until the certificate expires.
func (c *CertInfo) TimeUntilExpiry() time.Duration {
	return time.Until(c.Expiry)
}

// CertScanner lists and retrieves PKI certificates from Vault.
type CertScanner struct {
	client *Client
	mount  string
}

// NewCertScanner creates a CertScanner. Returns error if client is nil.
func NewCertScanner(client *Client, mount string) (*CertScanner, error) {
	if client == nil {
		return nil, fmt.Errorf("vault client must not be nil")
	}
	if mount == "" {
		mount = "pki"
	}
	return &CertScanner{client: client, mount: mount}, nil
}

// ListSerials returns all certificate serial numbers under the mount.
func (s *CertScanner) ListSerials() ([]string, error) {
	path := fmt.Sprintf("%s/certs", s.mount)
	secret, err := s.client.vault.Logical().List(path)
	if err != nil {
		return nil, fmt.Errorf("listing certs: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}
	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return []string{}, nil
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if s, ok := k.(string); ok {
			out = append(out, s)
		}
	}
	return out, nil
}

// GetCert retrieves certificate metadata by serial number.
func (s *CertScanner) GetCert(serial string) (*CertInfo, error) {
	if serial == "" {
		return nil, fmt.Errorf("serial must not be empty")
	}
	path := fmt.Sprintf("%s/cert/%s", s.mount, serial)
	secret, err := s.client.vault.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("reading cert %s: %w", serial, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("cert %s not found", serial)
	}
	expStr, _ := secret.Data["expiration"].(json.Number)
	expUnix, _ := expStr.Int64()
	return &CertInfo{
		Serial:     serial,
		CommonName: fmt.Sprintf("%v", secret.Data["common_name"]),
		Expiry:     time.Unix(expUnix, 0),
		Revoked:    secret.Data["revocation_time"] != nil,
	}, nil
}
