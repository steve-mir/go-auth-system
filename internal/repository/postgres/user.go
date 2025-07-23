package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/steve-mir/go-auth-system/internal/repository/postgres/db"
)

// UserRepository implements user data access using SQLC
type UserRepository struct {
	queries *db.Queries
}

// NewUserRepository creates a new user repository using SQLC
func NewUserRepository(database *DB) *UserRepository {
	return &UserRepository{
		queries: db.New(database.Primary()),
	}
}

// CreateUser creates a new user in the database
func (r *UserRepository) CreateUser(ctx context.Context, userData *CreateUserData) (*UserData, error) {
	params := db.CreateUserParams{
		Email:              userData.Email,
		PasswordHash:       userData.PasswordHash,
		HashAlgorithm:      userData.HashAlgorithm,
		FirstNameEncrypted: userData.FirstNameEncrypted,
		LastNameEncrypted:  userData.LastNameEncrypted,
		PhoneEncrypted:     userData.PhoneEncrypted,
	}

	// Set optional username
	if userData.Username != "" {
		params.Username = pgtype.Text{String: userData.Username, Valid: true}
	}

	user, err := r.queries.CreateUser(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return r.convertToUserData(user), nil
}

// GetUserByEmail retrieves a user by email
func (r *UserRepository) GetUserByEmail(ctx context.Context, email string) (*UserData, error) {
	user, err := r.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // User not found
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return r.convertToUserData(user), nil
}

// GetUserByUsername retrieves a user by username
func (r *UserRepository) GetUserByUsername(ctx context.Context, username string) (*UserData, error) {
	user, err := r.queries.GetUserByUsername(ctx, pgtype.Text{String: username, Valid: true})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // User not found
		}
		return nil, fmt.Errorf("failed to get user by username: %w", err)
	}

	return r.convertToUserData(user), nil
}

// GetUserByID retrieves a user by ID
func (r *UserRepository) GetUserByID(ctx context.Context, userID string) (*UserData, error) {
	id, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID format: %w", err)
	}

	user, err := r.queries.GetUserByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // User not found
		}
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	return r.convertToUserData(user), nil
}

// UpdateUser updates user information
func (r *UserRepository) UpdateUser(ctx context.Context, userID string, data *UpdateUserData) (*UserData, error) {
	id, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID format: %w", err)
	}

	params := db.UpdateUserParams{
		ID: id,
	}

	// Set fields that are being updated
	if data.Email != nil {
		params.Email = *data.Email
	}
	if data.Username != nil {
		params.Username = pgtype.Text{String: *data.Username, Valid: true}
	}
	if data.PasswordHash != nil {
		params.PasswordHash = *data.PasswordHash
	}
	if data.HashAlgorithm != nil {
		params.HashAlgorithm = *data.HashAlgorithm
	}
	if data.FirstNameEncrypted != nil {
		params.FirstNameEncrypted = data.FirstNameEncrypted
	}
	if data.LastNameEncrypted != nil {
		params.LastNameEncrypted = data.LastNameEncrypted
	}
	if data.PhoneEncrypted != nil {
		params.PhoneEncrypted = data.PhoneEncrypted
	}
	if data.EmailVerified != nil {
		params.EmailVerified = pgtype.Bool{Bool: *data.EmailVerified, Valid: true}
	}
	if data.PhoneVerified != nil {
		params.PhoneVerified = pgtype.Bool{Bool: *data.PhoneVerified, Valid: true}
	}
	// TODO: Variables missing in query
	// if data.AccountLocked != nil {
	// 	params.AccountLocked = pgtype.Bool{Bool: *data.AccountLocked, Valid: true}
	// }
	// if data.FailedAttempts != nil {
	// 	params.FailedLoginAttempts = pgtype.Int4{Int32: *data.FailedAttempts, Valid: true}
	// }

	user, err := r.queries.UpdateUser(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return r.convertToUserData(user), nil
}

// DeleteUser deletes a user
func (r *UserRepository) DeleteUser(ctx context.Context, userID string) error {
	id, err := uuid.Parse(userID)
	if err != nil {
		return fmt.Errorf("invalid user ID format: %w", err)
	}

	err = r.queries.DeleteUser(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	return nil
}

// ListUsers retrieves users with pagination
func (r *UserRepository) ListUsers(ctx context.Context, limit, offset int32) ([]*UserData, error) {
	params := db.ListUsersParams{
		Limit:  limit,
		Offset: offset,
	}

	users, err := r.queries.ListUsers(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	result := make([]*UserData, len(users))
	for i, user := range users {
		result[i] = r.convertToUserData(user)
	}

	return result, nil
}

// CountUsers returns total number of users
func (r *UserRepository) CountUsers(ctx context.Context) (int64, error) {
	count, err := r.queries.CountUsers(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to count users: %w", err)
	}

	return count, nil
}

// GetUserRoles retrieves roles for a user
func (r *UserRepository) GetUserRoles(ctx context.Context, userID string) ([]db.Role, error) {
	id, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID format: %w", err)
	}

	roles, err := r.queries.GetUserRoles(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	return roles, nil
}

// UpdateUserLoginInfo updates user login information
func (r *UserRepository) UpdateUserLoginInfo(ctx context.Context, userID string, info *LoginInfo) error {
	id, err := uuid.Parse(userID)
	if err != nil {
		return fmt.Errorf("invalid user ID format: %w", err)
	}

	params := db.UpdateUserLoginInfoParams{
		ID:                  id,
		FailedLoginAttempts: pgtype.Int4{Int32: info.FailedAttempts, Valid: true},
		AccountLocked:       pgtype.Bool{Bool: info.AccountLocked, Valid: true},
	}

	if info.LastLoginAt != nil {
		params.LastLoginAt = pgtype.Timestamp{Time: *info.LastLoginAt, Valid: true}
	}

	err = r.queries.UpdateUserLoginInfo(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to update user login info: %w", err)
	}

	return nil
}

// convertToUserData converts SQLC User model to service UserData
func (r *UserRepository) convertToUserData(user db.User) *UserData {
	userData := &UserData{
		ID:                 user.ID.String(),
		Email:              user.Email,
		PasswordHash:       user.PasswordHash,
		HashAlgorithm:      user.HashAlgorithm,
		FirstNameEncrypted: user.FirstNameEncrypted,
		LastNameEncrypted:  user.LastNameEncrypted,
		PhoneEncrypted:     user.PhoneEncrypted,
		CreatedAt:          user.CreatedAt.Time.Unix(),
		UpdatedAt:          user.UpdatedAt.Time.Unix(),
	}

	// Handle optional fields
	if user.Username.Valid {
		userData.Username = user.Username.String
	}
	if user.EmailVerified.Valid {
		userData.EmailVerified = user.EmailVerified.Bool
	}
	if user.PhoneVerified.Valid {
		userData.PhoneVerified = user.PhoneVerified.Bool
	}
	if user.AccountLocked.Valid {
		userData.AccountLocked = user.AccountLocked.Bool
	}
	if user.FailedLoginAttempts.Valid {
		userData.FailedAttempts = user.FailedLoginAttempts.Int32
	}
	if user.LastLoginAt.Valid {
		lastLogin := user.LastLoginAt.Time.Unix()
		userData.LastLoginAt = &lastLogin
	}

	return userData
}

// Data transfer objects for the repository layer
type CreateUserData struct {
	Email              string
	Username           string
	PasswordHash       string
	HashAlgorithm      string
	FirstNameEncrypted []byte
	LastNameEncrypted  []byte
	PhoneEncrypted     []byte
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
	AccountLocked      *bool
	FailedAttempts     *int32
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
	LastLoginAt    *time.Time
}
