package auth

import (
	"context"

	"github.com/steve-mir/go-auth-system/internal/security/crypto"
	"github.com/steve-mir/go-auth-system/internal/security/hash"
	"github.com/steve-mir/go-auth-system/internal/security/token"
)

// AuthService defines the interface for authentication operations
type AuthService interface {
	// Register creates a new user account with encrypted sensitive data
	Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error)

	// Login authenticates a user and returns tokens
	Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error)

	// Logout invalidates user session tokens
	Logout(ctx context.Context, req *LogoutRequest) error

	// RefreshToken generates new tokens using a valid refresh token
	RefreshToken(ctx context.Context, req *RefreshTokenRequest) (*TokenResponse, error)

	// ValidateToken validates a token and returns its claims
	ValidateToken(ctx context.Context, req *ValidateTokenRequest) (*ValidateTokenResponse, error)

	// GetUserProfile retrieves user profile information from token
	GetUserProfile(ctx context.Context, token string) (*UserProfile, error)

	// GetUserSessions retrieves active sessions for a user
	GetUserSessions(ctx context.Context, userID string) ([]*SessionInfo, error)

	// RevokeUserSessions revokes all sessions for a user
	RevokeUserSessions(ctx context.Context, userID string) error

	// RevokeSession revokes a specific session
	RevokeSession(ctx context.Context, sessionID string) error
}

// Repository interfaces that the auth service depends on
type UserRepository interface {
	// CreateUser creates a new user in the database
	CreateUser(ctx context.Context, user *CreateUserData) (*UserData, error)

	// GetUserByEmail retrieves a user by email
	GetUserByEmail(ctx context.Context, email string) (*UserData, error)

	// GetUserByUsername retrieves a user by username
	GetUserByUsername(ctx context.Context, username string) (*UserData, error)

	// GetUserByID retrieves a user by ID
	GetUserByID(ctx context.Context, userID string) (*UserData, error)

	// UpdateUserLoginInfo updates user login information
	UpdateUserLoginInfo(ctx context.Context, userID string, info *LoginInfo) error

	// GetUserRoles retrieves roles for a user
	GetUserRoles(ctx context.Context, userID string) ([]string, error)
}

// SessionRepository interface for session management
type SessionRepository interface {
	// CreateSession creates a new session
	CreateSession(ctx context.Context, session *SessionData) error

	// GetSession retrieves a session by ID
	GetSession(ctx context.Context, sessionID string) (*SessionData, error)

	// UpdateSession updates session information
	UpdateSession(ctx context.Context, sessionID string, session *SessionData) error

	// DeleteSession deletes a session
	DeleteSession(ctx context.Context, sessionID string) error

	// DeleteUserSessions deletes all sessions for a user
	DeleteUserSessions(ctx context.Context, userID string) error

	// GetUserSessions retrieves all sessions for a user
	GetUserSessions(ctx context.Context, userID string) ([]*SessionData, error)
}

// TokenBlacklistRepository interface for token blacklisting
type TokenBlacklistRepository interface {
	// BlacklistToken adds a token to the blacklist
	BlacklistToken(ctx context.Context, tokenHash string, expiresAt int64, reason string) error

	// IsTokenBlacklisted checks if a token is blacklisted
	IsTokenBlacklisted(ctx context.Context, tokenHash string) (bool, error)

	// BlacklistUserTokens blacklists all tokens for a user
	BlacklistUserTokens(ctx context.Context, userID string, reason string) error
}

// Data transfer objects
type CreateUserData struct {
	Email              string
	Username           string
	PasswordHash       string
	HashAlgorithm      string
	FirstNameEncrypted []byte
	LastNameEncrypted  []byte
	PhoneEncrypted     []byte
}

type UserData struct {
	ID                 string
	Email              string
	Username           string
	PasswordHash       string
	HashAlgorithm      string
	FirstNameEncrypted []byte
	LastNameEncrypted  []byte
	PhoneEncrypted     []byte
	EmailVerified      bool
	PhoneVerified      bool
	AccountLocked      bool
	FailedAttempts     int32
	LastLoginAt        *int64
	CreatedAt          int64
	UpdatedAt          int64
}

type LoginInfo struct {
	FailedAttempts int32
	AccountLocked  bool
	LastLoginAt    *int64
}

type SessionData struct {
	ID        string
	UserID    string
	TokenHash string
	TokenType string
	Roles     []string
	ExpiresAt int64
	IPAddress string
	UserAgent string
	CreatedAt int64
	LastUsed  int64
}

// Dependencies interface for external services
type Dependencies struct {
	UserRepo      UserRepository
	SessionRepo   SessionRepository
	BlacklistRepo TokenBlacklistRepository
	TokenService  token.TokenService
	HashService   HashService
	Encryptor     Encryptor
}

// Use the hash package service
type HashService = hash.HashService

// Use the crypto package encryptor
type Encryptor = crypto.Encryptor
