package token

import (
	"context"
	"time"
)

// TokenType represents the type of token
type TokenType string

const (
	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh"
)

// TokenClaims represents the claims contained in a token
type TokenClaims struct {
	UserID    string            `json:"user_id"`
	Email     string            `json:"email"`
	Username  string            `json:"username,omitempty"`
	Roles     []string          `json:"roles,omitempty"`
	TokenType TokenType         `json:"token_type"`
	IssuedAt  time.Time         `json:"issued_at"`
	ExpiresAt time.Time         `json:"expires_at"`
	Issuer    string            `json:"issuer"`
	Audience  string            `json:"audience"`
	Subject   string            `json:"subject"`
	JTI       string            `json:"jti"` // JWT ID for token tracking
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// TokenPair represents an access and refresh token pair
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"` // "Bearer"
	ExpiresIn    int64     `json:"expires_in"` // Access token expiry in seconds
	ExpiresAt    time.Time `json:"expires_at"` // Access token expiry timestamp
}

// TokenService defines the interface for token management operations
type TokenService interface {
	// GenerateTokens creates a new access and refresh token pair
	GenerateTokens(ctx context.Context, userID string, claims TokenClaims) (*TokenPair, error)

	// ValidateToken validates a token and returns its claims
	ValidateToken(ctx context.Context, token string) (*TokenClaims, error)

	// RefreshToken generates a new token pair using a valid refresh token
	RefreshToken(ctx context.Context, refreshToken string) (*TokenPair, error)

	// RevokeToken revokes a token (adds it to blacklist)
	RevokeToken(ctx context.Context, token string) error

	// IsTokenRevoked checks if a token has been revoked
	IsTokenRevoked(ctx context.Context, tokenID string) (bool, error)

	// GetTokenClaims extracts claims from a token without validation
	GetTokenClaims(ctx context.Context, token string) (*TokenClaims, error)

	// GetTokenType returns the token service type (jwt or paseto)
	GetTokenType() string
}

// TokenValidator defines validation-specific operations
type TokenValidator interface {
	// ValidateTokenFormat validates the token format without checking signature
	ValidateTokenFormat(token string) error

	// ValidateTokenClaims validates the token claims
	ValidateTokenClaims(claims *TokenClaims) error
}

// TokenGenerator defines token generation operations
type TokenGenerator interface {
	// GenerateAccessToken creates an access token
	GenerateAccessToken(claims TokenClaims) (string, error)

	// GenerateRefreshToken creates a refresh token
	GenerateRefreshToken(claims TokenClaims) (string, error)
}
