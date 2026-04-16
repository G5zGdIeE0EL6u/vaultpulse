package vault

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// AuthMethod represents a Vault auth method type.
type AuthMethod string

const (
	AuthToken      AuthMethod = "token"
	AuthAppRole    AuthMethod = "approle"
	AuthKubernetes AuthMethod = "kubernetes"
)

// AuthInfo holds the result of a successful authentication.
type AuthInfo struct {
	Token     string
	LeaseTTL  time.Duration
	Renewable bool
	Method    AuthMethod
}

// IsExpired returns true if the lease TTL is zero or negative.
func (a *AuthInfo) IsExpired() bool {
	return a.LeaseTTL <= 0
}

// AuthenticatorConfig holds configuration for an auth method.
type AuthenticatorConfig struct {
	Method   AuthMethod
	RoleID   string
	SecretID string
	Token    string
}

// Authenticator handles Vault authentication.
type Authenticator struct {
	client *Client
}

// NewAuthenticator creates a new Authenticator.
func NewAuthenticator(client *Client) (*Authenticator, error) {
	if client == nil {
		return nil, errors.New("vault client must not be nil")
	}
	return &Authenticator{client: client}, nil
}

// Authenticate performs authentication using the given config and returns AuthInfo.
func (a *Authenticator) Authenticate(ctx context.Context, cfg AuthenticatorConfig) (*AuthInfo, error) {
	switch cfg.Method {
	case AuthToken:
		if cfg.Token == "" {
			return nil, errors.New("token must not be empty")
		}
		return &AuthInfo{
			Token:     cfg.Token,
			LeaseTTL:  0,
			Renewable: false,
			Method:    AuthToken,
		}, nil
	case AuthAppRole:
		if cfg.RoleID == "" || cfg.SecretID == "" {
			return nil, errors.New("role_id and secret_id are required for approle auth")
		}
		path := "auth/approle/login"
		data := map[string]interface{}{
			"role_id":   cfg.RoleID,
			"secret_id": cfg.SecretID,
		}
		secret, err := a.client.vault.Logical().WriteWithContext(ctx, path, data)
		if err != nil {
			return nil, fmt.Errorf("approle login failed: %w", err)
		}
		if secret == nil || secret.Auth == nil {
			return nil, errors.New("empty auth response from vault")
		}
		return &AuthInfo{
			Token:     secret.Auth.ClientToken,
			LeaseTTL:  time.Duration(secret.Auth.LeaseDuration) * time.Second,
			Renewable: secret.Auth.Renewable,
			Method:    AuthAppRole,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported auth method: %s", cfg.Method)
	}
}
