package user

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/steve-mir/go-auth-system/internal/errors"
	"github.com/steve-mir/go-auth-system/internal/repository/postgres"
	"github.com/steve-mir/go-auth-system/internal/repository/postgres/db"
	"github.com/steve-mir/go-auth-system/internal/repository/redis"
)

// PostgresUserRepository adapts SQLC queries to UserRepository interface
type PostgresUserRepository struct {
	queries *postgres.DB
	store   *db.Store
}

// NewPostgresUserRepository creates a new PostgreSQL user repository
func NewPostgresUserRepository(queries *postgres.DB, store *db.Store) UserRepository {
	return &PostgresUserRepository{
		queries: queries,
		store:   store,
	}
}

func (r *PostgresUserRepository) GetUserByID(ctx context.Context, userID string) (*UserData, error) {
	id, err := uuid.Parse(userID)
	if err != nil {
		return nil, errors.New(errors.ErrorTypeValidation, "INVALID_USER_ID", "Invalid user ID format")
	}

	dbUser, err := r.store.GetUserByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, sql.ErrNoRows
		}
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	return r.convertDBUserToUserData(&dbUser), nil
}

func (r *PostgresUserRepository) GetUserByEmail(ctx context.Context, email string) (*UserData, error) {
	dbUser, err := r.store.GetUserByEmail(ctx, email)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, sql.ErrNoRows
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return r.convertDBUserToUserData(&dbUser), nil
}

func (r *PostgresUserRepository) GetUserByUsername(ctx context.Context, username string) (*UserData, error) {
	dbUser, err := r.store.GetUserByUsername(ctx, pgtype.Text{String: username, Valid: true})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, sql.ErrNoRows
		}
		return nil, fmt.Errorf("failed to get user by username: %w", err)
	}

	return r.convertDBUserToUserData(&dbUser), nil
}

func (r *PostgresUserRepository) UpdateUser(ctx context.Context, userID string, data *UpdateUserData) (*UserData, error) {
	id, err := uuid.Parse(userID)
	if err != nil {
		return nil, errors.New(errors.ErrorTypeValidation, "INVALID_USER_ID", "Invalid user ID format")
	}

	// Get current user to preserve existing values
	currentUser, err := r.store.GetUserByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get current user: %w", err)
	}

	// Build update parameters, preserving existing values where not updated
	params := db.UpdateUserParams{
		ID:                 id,
		Email:              currentUser.Email,
		Username:           currentUser.Username,
		PasswordHash:       currentUser.PasswordHash,
		HashAlgorithm:      currentUser.HashAlgorithm,
		FirstNameEncrypted: currentUser.FirstNameEncrypted,
		LastNameEncrypted:  currentUser.LastNameEncrypted,
		PhoneEncrypted:     currentUser.PhoneEncrypted,
		EmailVerified:      currentUser.EmailVerified,
		PhoneVerified:      currentUser.PhoneVerified,
	}

	// Apply updates
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

	dbUser, err := r.store.UpdateUser(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return r.convertDBUserToUserData(&dbUser), nil
}

func (r *PostgresUserRepository) DeleteUser(ctx context.Context, userID string) error {
	id, err := uuid.Parse(userID)
	if err != nil {
		return errors.New(errors.ErrorTypeValidation, "INVALID_USER_ID", "Invalid user ID format")
	}

	return r.store.DeleteUser(ctx, id)
}

func (r *PostgresUserRepository) ListUsers(ctx context.Context, limit, offset int32) ([]*UserData, error) {
	params := db.ListUsersParams{
		Limit:  limit,
		Offset: offset,
	}

	dbUsers, err := r.store.ListUsers(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	users := make([]*UserData, 0, len(dbUsers))
	for _, dbUser := range dbUsers {
		users = append(users, r.convertDBUserToUserData(&dbUser))
	}

	return users, nil
}

func (r *PostgresUserRepository) CountUsers(ctx context.Context) (int64, error) {
	return r.store.CountUsers(ctx)
}

func (r *PostgresUserRepository) GetUsersByRole(ctx context.Context, roleName string) ([]*UserData, error) {
	dbUsers, err := r.store.GetUsersByRole(ctx, roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to get users by role: %w", err)
	}

	users := make([]*UserData, 0, len(dbUsers))
	for _, dbUser := range dbUsers {
		users = append(users, r.convertDBUserToUserData(&dbUser))
	}

	return users, nil
}

func (r *PostgresUserRepository) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	id, err := uuid.Parse(userID)
	if err != nil {
		return nil, errors.New(errors.ErrorTypeValidation, "INVALID_USER_ID", "Invalid user ID format")
	}

	roles, err := r.store.GetUserRoles(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	roleNames := make([]string, 0, len(roles))
	for _, role := range roles {
		roleNames = append(roleNames, role.Name)
	}

	return roleNames, nil
}

func (r *PostgresUserRepository) convertDBUserToUserData(dbUser *db.User) *UserData {
	var username string
	if dbUser.Username.Valid {
		username = dbUser.Username.String
	}

	var emailVerified, phoneVerified, accountLocked bool
	var failedAttempts int32
	var lastLoginAt *int64

	if dbUser.EmailVerified.Valid {
		emailVerified = dbUser.EmailVerified.Bool
	}
	if dbUser.PhoneVerified.Valid {
		phoneVerified = dbUser.PhoneVerified.Bool
	}
	if dbUser.AccountLocked.Valid {
		accountLocked = dbUser.AccountLocked.Bool
	}
	if dbUser.FailedLoginAttempts.Valid {
		failedAttempts = dbUser.FailedLoginAttempts.Int32
	}
	if dbUser.LastLoginAt.Valid {
		timestamp := dbUser.LastLoginAt.Time.Unix()
		lastLoginAt = &timestamp
	}

	var createdAt, updatedAt int64
	if dbUser.CreatedAt.Valid {
		createdAt = dbUser.CreatedAt.Time.Unix()
	}
	if dbUser.UpdatedAt.Valid {
		updatedAt = dbUser.UpdatedAt.Time.Unix()
	}

	return &UserData{
		ID:                 dbUser.ID.String(),
		Email:              dbUser.Email,
		Username:           username,
		PasswordHash:       dbUser.PasswordHash,
		HashAlgorithm:      dbUser.HashAlgorithm,
		FirstNameEncrypted: dbUser.FirstNameEncrypted,
		LastNameEncrypted:  dbUser.LastNameEncrypted,
		PhoneEncrypted:     dbUser.PhoneEncrypted,
		EmailVerified:      emailVerified,
		PhoneVerified:      phoneVerified,
		AccountLocked:      accountLocked,
		FailedAttempts:     failedAttempts,
		LastLoginAt:        lastLoginAt,
		CreatedAt:          createdAt,
		UpdatedAt:          updatedAt,
	}
}

// RedisSessionRepository adapts Redis session store to SessionRepository interface
type RedisSessionRepository struct {
	sessionStore *redis.SessionStore
}

// NewRedisSessionRepository creates a new Redis session repository
func NewRedisSessionRepository(sessionStore *redis.SessionStore) SessionRepository {
	return &RedisSessionRepository{
		sessionStore: sessionStore,
	}
}

func (r *RedisSessionRepository) DeleteUserSessions(ctx context.Context, userID string) error {
	return r.sessionStore.DeleteUserSessions(ctx, userID)
}

// PostgresAuditRepository adapts SQLC queries to AuditRepository interface
type PostgresAuditRepository struct {
	queries *postgres.DB
	store   *db.Store
}

// NewPostgresAuditRepository creates a new PostgreSQL audit repository
func NewPostgresAuditRepository(queries *postgres.DB, store *db.Store) AuditRepository {
	return &PostgresAuditRepository{
		queries: queries,
		store:   store,
	}
}

func (r *PostgresAuditRepository) LogUserAction(ctx context.Context, action *AuditLogData) error {
	//TODO: This would require implementing audit log creation
	// For now, we'll just return nil as audit functionality is in a later task
	return nil
}
