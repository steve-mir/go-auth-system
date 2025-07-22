package sso

import (
	"context"
)

// SSOService defines the interface for single sign-on operations
type SSOService interface {
	// OAuth Social Authentication
	GetOAuthURL(ctx context.Context, provider string, state string) (string, error)
	HandleOAuthCallback(ctx context.Context, provider, code, state string) (*OAuthResult, error)

	// User account linking
	LinkSocialAccount(ctx context.Context, userID string, provider string, socialID string) error
	UnlinkSocialAccount(ctx context.Context, userID string, provider string) error
	GetLinkedAccounts(ctx context.Context, userID string) ([]LinkedAccount, error)

	// SAML 2.0 Service Provider
	GetSAMLMetadata(ctx context.Context) ([]byte, error)
	InitiateSAMLLogin(ctx context.Context, idpEntityID string, relayState string) (*SAMLAuthRequest, error)
	HandleSAMLResponse(ctx context.Context, samlResponse string, relayState string) (*SAMLResult, error)
	ValidateSAMLAssertion(ctx context.Context, assertion *SAMLAssertion) error

	// OpenID Connect
	GetOIDCAuthURL(ctx context.Context, provider string, state string, nonce string) (string, error)
	HandleOIDCCallback(ctx context.Context, provider, code, state string) (*OIDCResult, error)
	ValidateOIDCIDToken(ctx context.Context, provider, idToken string) (*OIDCIDTokenClaims, error)
	RefreshOIDCToken(ctx context.Context, provider, refreshToken string) (*OIDCTokenResponse, error)
}

// OAuthResult represents the result of OAuth authentication
type OAuthResult struct {
	UserID       string            `json:"user_id"`
	Email        string            `json:"email"`
	Name         string            `json:"name"`
	Provider     string            `json:"provider"`
	SocialID     string            `json:"social_id"`
	IsNewUser    bool              `json:"is_new_user"`
	AccessToken  string            `json:"access_token"`
	RefreshToken string            `json:"refresh_token"`
	ExpiresAt    int64             `json:"expires_at"`
	Metadata     map[string]string `json:"metadata"`
}

// LinkedAccount represents a linked social account
type LinkedAccount struct {
	Provider string `json:"provider"`
	SocialID string `json:"social_id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	LinkedAt int64  `json:"linked_at"`
}

// OAuthProvider represents an OAuth provider configuration
type OAuthProvider interface {
	GetAuthURL(state string) string
	ExchangeCode(ctx context.Context, code string) (*OAuthToken, error)
	GetUserInfo(ctx context.Context, token *OAuthToken) (*UserInfo, error)
	GetProviderName() string
}

// OAuthToken represents an OAuth access token
type OAuthToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// UserInfo represents user information from OAuth provider
type UserInfo struct {
	ID       string            `json:"id"`
	Email    string            `json:"email"`
	Name     string            `json:"name"`
	Picture  string            `json:"picture"`
	Verified bool              `json:"verified"`
	Metadata map[string]string `json:"metadata"`
}
