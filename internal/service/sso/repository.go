package sso

import (
	"context"
)

// SocialAccountRepository defines the interface for social account data operations
type SocialAccountRepository interface {
	// CreateSocialAccount creates a new social account link
	CreateSocialAccount(ctx context.Context, account *SocialAccount) error

	// GetSocialAccountByProviderAndSocialID retrieves a social account by provider and social ID
	GetSocialAccountByProviderAndSocialID(ctx context.Context, provider, socialID string) (*SocialAccount, error)

	// GetSocialAccountsByUserID retrieves all social accounts for a user
	GetSocialAccountsByUserID(ctx context.Context, userID string) ([]*SocialAccount, error)

	// GetSocialAccountByUserIDAndProvider retrieves a social account by user ID and provider
	GetSocialAccountByUserIDAndProvider(ctx context.Context, userID, provider string) (*SocialAccount, error)

	// UpdateSocialAccount updates a social account
	UpdateSocialAccount(ctx context.Context, account *SocialAccount) error

	// DeleteSocialAccount deletes a social account
	DeleteSocialAccount(ctx context.Context, userID, provider string) error

	// DeleteAllUserSocialAccounts deletes all social accounts for a user
	DeleteAllUserSocialAccounts(ctx context.Context, userID string) error
}

// UserRepository defines the interface for user operations needed by SSO service
type UserRepository interface {
	// GetUserByEmail retrieves a user by email
	GetUserByEmail(ctx context.Context, email string) (*UserData, error)

	// CreateUser creates a new user
	CreateUser(ctx context.Context, user *CreateUserData) (*UserData, error)

	// UpdateUser updates an existing user
	UpdateUser(ctx context.Context, user *UpdateUserData) error
}

// UserData represents user data from the repository
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

// CreateUserData represents data for creating a new user
type CreateUserData struct {
	Email         string
	Username      string
	PasswordHash  string
	HashAlgorithm string
	FirstName     string
	LastName      string
	Phone         string
	EmailVerified bool
	PhoneVerified bool
}

// UpdateUserData represents data for updating an existing user
type UpdateUserData struct {
	ID        string
	FirstName string
	LastName  string
	Phone     string
}
