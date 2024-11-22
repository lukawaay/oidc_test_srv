package impl

import (
	"time"

	"github.com/lukawaay/oidc_test_srv/internal/server/config"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type Client struct {
	cfg config.Client
}

func (c *Client) GetID() string {
	return c.cfg.ID
}

func (c *Client) RedirectURIs() []string {
	return c.cfg.RedirectURIs
}

func (c *Client) PostLogoutRedirectURIs() []string {
	return c.cfg.PostLogoutRedirectURIs
}

func (c *Client) ApplicationType() op.ApplicationType {
	return c.cfg.ApplicationType
}

func (c *Client) AuthMethod() oidc.AuthMethod {
	return c.cfg.AuthMethod
}

func (c *Client) ResponseTypes() []oidc.ResponseType {
	return c.cfg.ResponseTypes
}

func (c *Client) GrantTypes() []oidc.GrantType {
	return c.cfg.GrantTypes
}

func (c *Client) LoginURL(id string) string {
	return config.LoginWithID(id)
}

func (c *Client) AccessTokenType() op.AccessTokenType {
	return op.AccessTokenTypeBearer
}

func (c *Client) IDTokenLifetime() time.Duration {
	return 1 * time.Hour
}

func (c *Client) DevMode() bool {
	return false
}

func (c *Client) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string {
		return scopes
	}
}

func (c *Client) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string {
		return scopes
	}
}

func (c *Client) IsScopeAllowed(scope string) bool {
	return true
}

func (c *Client) IDTokenUserinfoClaimsAssertion() bool {
	return false
}

func (c *Client) ClockSkew() time.Duration {
	return 0
}
