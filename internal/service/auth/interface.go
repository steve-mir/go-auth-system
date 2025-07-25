package auth

import (
	"context"

	"github.com/steve-mir/go-auth-system/internal/interfaces"
	"github.com/steve-mir/go-auth-system/internal/security/crypto"
	"github.com/steve-mir/go-auth-system/internal/security/hash"
	"github.com/steve-mir/go-auth-system/internal/security/token"
)

// Repository interfaces that the auth service depends on
type UserRepository interface {
	// CreateUser creates a new user in the database
	CreateUser(ctx context.Context, user *interfaces.CreateUserData) (*interfaces.UserData, error)

	// GetUserByEmail retrieves a user by email
	GetUserByEmail(ctx context.Context, email string) (*interfaces.UserData, error)

	// GetUserByUsername retrieves a user by username
	GetUserByUsername(ctx context.Context, username string) (*interfaces.UserData, error)

	// GetUserByID retrieves a user by ID
	GetUserByID(ctx context.Context, userID string) (*interfaces.UserData, error)

	// UpdateUser updates user profile information
	UpdateUser(ctx context.Context, user *interfaces.UpdateUserData) error

	// UpdateUserLoginInfo updates user login information
	UpdateUserLoginInfo(ctx context.Context, userID string, info *interfaces.LoginInfo) error

	// GetUserRoles retrieves roles for a user
	GetUserRoles(ctx context.Context, userID string) ([]string, error)
}

// SessionRepository interface for session management
type SessionRepository interface {
	// CreateSession creates a new session
	CreateSession(ctx context.Context, session *interfaces.SessionData) error

	// GetSession retrieves a session by ID
	GetSession(ctx context.Context, sessionID string) (*interfaces.SessionData, error)

	// UpdateSession updates session information
	UpdateSession(ctx context.Context, sessionID string, session *interfaces.SessionData) error

	// DeleteSession deletes a session
	DeleteSession(ctx context.Context, sessionID string) error

	// DeleteUserSessions deletes all sessions for a user
	DeleteUserSessions(ctx context.Context, userID string) error

	// GetUserSessions retrieves all sessions for a user
	GetUserSessions(ctx context.Context, userID string) ([]*interfaces.SessionData, error)
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
