package interfaces

import (
	"context"
	"time"

	"github.com/google/uuid"
)

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

// RegisterRequest represents a user registration request
type RegisterRequest struct {
	Email     string `json:"email" validate:"required,email"`
	Username  string `json:"username,omitempty" validate:"omitempty,min=3,max=50"`
	Password  string `json:"password" validate:"required,min=8"`
	FirstName string `json:"first_name,omitempty" validate:"omitempty,max=100"`
	LastName  string `json:"last_name,omitempty" validate:"omitempty,max=100"`
	Phone     string `json:"phone,omitempty" validate:"omitempty,e164"`
	IPAddress string `json:"-"` // Set programmatically
	UserAgent string `json:"-"` // Set programmatically
}

// RegisterResponse represents a user registration response
type RegisterResponse struct {
	UserID    uuid.UUID `json:"user_id"`
	Email     string    `json:"email"`
	Username  string    `json:"username,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	Message   string    `json:"message"`
}

// LoginRequest represents a user login request
type LoginRequest struct {
	Email      string `json:"email,omitempty" validate:"omitempty,email"`
	Username   string `json:"username,omitempty" validate:"omitempty,min=3"`
	Password   string `json:"password" validate:"required"`
	IPAddress  string `json:"ip_address,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
	RememberMe bool   `json:"remember_me,omitempty"`
}

// LoginResponse represents a user login response
type LoginResponse struct {
	UserID       uuid.UUID `json:"user_id"`
	Email        string    `json:"email"`
	Username     string    `json:"username,omitempty"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int64     `json:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// LogoutRequest represents a user logout request
type LogoutRequest struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	AllSessions  bool   `json:"all_sessions,omitempty"`
}

// RefreshTokenRequest represents a token refresh request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
	IPAddress    string `json:"ip_address,omitempty"`
	UserAgent    string `json:"user_agent,omitempty"`
}

// TokenResponse represents a token response
type TokenResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int64     `json:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// ValidateTokenRequest represents a token validation request
type ValidateTokenRequest struct {
	Token string `json:"token" validate:"required"`
}

// ValidateTokenResponse represents a token validation response
type ValidateTokenResponse struct {
	Valid     bool                   `json:"valid"`
	UserID    string                 `json:"user_id,omitempty"`
	Email     string                 `json:"email,omitempty"`
	Username  string                 `json:"username,omitempty"`
	Roles     []string               `json:"roles,omitempty"`
	ExpiresAt time.Time              `json:"expires_at,omitempty"`
	Metadata  map[string]string      `json:"metadata,omitempty"`
	Claims    map[string]interface{} `json:"claims,omitempty"`
}

// UserProfile represents basic user profile information
// type UserProfile struct {
// 	ID        uuid.UUID `json:"id"`
// 	Email     string    `json:"email"`
// 	Username  string    `json:"username,omitempty"`
// 	FirstName string    `json:"first_name,omitempty"`
// 	LastName  string    `json:"last_name,omitempty"`
// 	Phone     string    `json:"phone,omitempty"`
// 	Roles     []string  `json:"roles,omitempty"`
// 	CreatedAt time.Time `json:"created_at"`
// 	UpdatedAt time.Time `json:"updated_at"`
// }

// SessionInfo represents session information
type SessionInfo struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	IPAddress string    `json:"ip_address,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used"`
	ExpiresAt time.Time `json:"expires_at"`
}

// UpdateUserData represents data for updating an existing user
type UpdateUserData struct {
	ID                 string
	Email              string
	Username           string
	FirstNameEncrypted []byte
	LastNameEncrypted  []byte
	PhoneEncrypted     []byte
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
