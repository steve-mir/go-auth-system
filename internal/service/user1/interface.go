package user1

import (
	"context"

	"github.com/steve-mir/go-auth-system/internal/security/crypto"
	"github.com/steve-mir/go-auth-system/internal/security/hash"
)

// UserService defines the interface for user management operations
type UserService interface {
	// GetProfile retrieves user profile information by user ID
	GetProfile(ctx context.Context, userID string) (*UserProfile, error)

	// UpdateProfile updates user profile information with data encryption
	UpdateProfile(ctx context.Context, userID string, req *UpdateProfileRequest) (*UserProfile, error)

	// DeleteUser deletes a user and performs proper cleanup
	DeleteUser(ctx context.Context, userID string) error

	// ListUsers retrieves users with pagination and filtering
	ListUsers(ctx context.Context, req *ListUsersRequest) (*ListUsersResponse, error)

	// ChangePassword allows users to change their password
	ChangePassword(ctx context.Context, userID string, req *ChangePasswordRequest) error

	// GetUserRoles retrieves roles assigned to a user
	GetUserRoles(ctx context.Context, userID string) ([]string, error)
}

// Repository interfaces that the user service depends on
type UserRepository interface {
	// GetUserByID retrieves a user by ID
	GetUserByID(ctx context.Context, userID string) (*UserData, error)

	// GetUserByEmail retrieves a user by email
	GetUserByEmail(ctx context.Context, email string) (*UserData, error)

	// GetUserByUsername retrieves a user by username
	GetUserByUsername(ctx context.Context, username string) (*UserData, error)

	// UpdateUser updates user information
	UpdateUser(ctx context.Context, userID string, data *UpdateUserData) (*UserData, error)

	// DeleteUser deletes a user
	DeleteUser(ctx context.Context, userID string) error

	// ListUsers retrieves users with pagination
	ListUsers(ctx context.Context, limit, offset int32) ([]*UserData, error)

	// CountUsers returns total number of users
	CountUsers(ctx context.Context) (int64, error)

	// GetUsersByRole retrieves users by role
	GetUsersByRole(ctx context.Context, roleName string) ([]*UserData, error)

	// GetUserRoles retrieves roles for a user
	GetUserRoles(ctx context.Context, userID string) ([]string, error)
}

// SessionRepository interface for session cleanup
type SessionRepository interface {
	// DeleteUserSessions deletes all sessions for a user
	DeleteUserSessions(ctx context.Context, userID string) error
}

// AuditRepository interface for audit logging
type AuditRepository interface {
	// LogUserAction logs user management actions
	LogUserAction(ctx context.Context, action *AuditLogData) error
}

// Data transfer objects
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

type UpdateUserData struct {
	Email              *string
	Username           *string
	PasswordHash       *string
	HashAlgorithm      *string
	FirstNameEncrypted []byte
	LastNameEncrypted  []byte
	PhoneEncrypted     []byte
	EmailVerified      *bool
	PhoneVerified      *bool
}

type AuditLogData struct {
	UserID       string
	Action       string
	ResourceType string
	ResourceID   string
	IPAddress    string
	UserAgent    string
	Metadata     map[string]interface{}
}

// Dependencies interface for external services
type Dependencies struct {
	UserRepo    UserRepository
	SessionRepo SessionRepository
	AuditRepo   AuditRepository
	HashService hash.HashService
	Encryptor   crypto.Encryptor
}
