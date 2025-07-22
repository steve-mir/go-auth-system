package auth

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/steve-mir/go-auth-system/internal/errors"
	"github.com/steve-mir/go-auth-system/internal/repository/postgres/db"
	"github.com/steve-mir/go-auth-system/internal/repository/redis"
)

// PostgresUserRepository adapts SQLC queries to UserRepository interface
type PostgresUserRepository struct {
	queries *db.Queries
}

// NewPostgresUserRepository creates a new PostgreSQL user repository
func NewPostgresUserRepository(queries *db.Queries) UserRepository {
	return &PostgresUserRepository{
		queries: queries,
	}
}

func (r *PostgresUserRepository) CreateUser(ctx context.Context, user *CreateUserData) (*UserData, error) {
	var username pgtype.Text
	if user.Username != "" {
		username = pgtype.Text{String: user.Username, Valid: true}
	}

	params := db.CreateUserParams{
		Email:              user.Email,
		Username:           username,
		PasswordHash:       user.PasswordHash,
		HashAlgorithm:      user.HashAlgorithm,
		FirstNameEncrypted: user.FirstNameEncrypted,
		LastNameEncrypted:  user.LastNameEncrypted,
		PhoneEncrypted:     user.PhoneEncrypted,
	}

	dbUser, err := r.queries.CreateUser(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return r.convertDBUserToUserData(&dbUser), nil
}

func (r *PostgresUserRepository) GetUserByEmail(ctx context.Context, email string) (*UserData, error) {
	dbUser, err := r.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New(errors.ErrorTypeNotFound, "USER_NOT_FOUND", "User not found")
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return r.convertDBUserToUserData(&dbUser), nil
}

func (r *PostgresUserRepository) GetUserByUsername(ctx context.Context, username string) (*UserData, error) {
	usernameParam := pgtype.Text{String: username, Valid: true}
	dbUser, err := r.queries.GetUserByUsername(ctx, usernameParam)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New(errors.ErrorTypeNotFound, "USER_NOT_FOUND", "User not found")
		}
		return nil, fmt.Errorf("failed to get user by username: %w", err)
	}

	return r.convertDBUserToUserData(&dbUser), nil
}

func (r *PostgresUserRepository) GetUserByID(ctx context.Context, userID string) (*UserData, error) {
	id, err := uuid.Parse(userID)
	if err != nil {
		return nil, errors.New(errors.ErrorTypeValidation, "INVALID_USER_ID", "Invalid user ID format")
	}

	dbUser, err := r.queries.GetUserByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New(errors.ErrorTypeNotFound, "USER_NOT_FOUND", "User not found")
		}
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	return r.convertDBUserToUserData(&dbUser), nil
}

func (r *PostgresUserRepository) UpdateUserLoginInfo(ctx context.Context, userID string, info *LoginInfo) error {
	id, err := uuid.Parse(userID)
	if err != nil {
		return errors.New(errors.ErrorTypeValidation, "INVALID_USER_ID", "Invalid user ID format")
	}

	var lastLoginAt pgtype.Timestamp
	if info.LastLoginAt != nil {
		lastLoginAt = pgtype.Timestamp{Time: time.Unix(*info.LastLoginAt, 0), Valid: true}
	}

	params := db.UpdateUserLoginInfoParams{
		ID:                  id,
		FailedLoginAttempts: pgtype.Int4{Int32: info.FailedAttempts, Valid: true},
		AccountLocked:       pgtype.Bool{Bool: info.AccountLocked, Valid: true},
		LastLoginAt:         lastLoginAt,
	}

	return r.queries.UpdateUserLoginInfo(ctx, params)
}

func (r *PostgresUserRepository) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	// Parse userID to UUID
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, err
	}

	// Get user roles from database
	roles, err := r.queries.GetUserRoles(ctx, uid)
	if err != nil {
		return nil, err
	}

	// Convert to string slice
	roleNames := make([]string, len(roles))
	for i, role := range roles {
		roleNames[i] = role.Name
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

func (r *RedisSessionRepository) CreateSession(ctx context.Context, session *SessionData) error {
	redisSession := &redis.SessionData{
		UserID:    session.UserID,
		Roles:     session.Roles, // Now properly populated with user roles
		IPAddress: session.IPAddress,
		UserAgent: session.UserAgent,
		CreatedAt: time.Unix(session.CreatedAt, 0),
		LastUsed:  time.Unix(session.LastUsed, 0),
	}

	ttl := time.Unix(session.ExpiresAt, 0).Sub(time.Unix(session.CreatedAt, 0))
	return r.sessionStore.Store(ctx, session.ID, redisSession, ttl)
}

func (r *RedisSessionRepository) GetSession(ctx context.Context, sessionID string) (*SessionData, error) {
	redisSession, err := r.sessionStore.Get(ctx, sessionID)
	if err != nil {
		return nil, errors.New(errors.ErrorTypeNotFound, "SESSION_NOT_FOUND", "Session not found")
	}

	return &SessionData{
		ID:        sessionID,
		UserID:    redisSession.UserID,
		IPAddress: redisSession.IPAddress,
		UserAgent: redisSession.UserAgent,
		CreatedAt: redisSession.CreatedAt.Unix(),
		LastUsed:  redisSession.LastUsed.Unix(),
		ExpiresAt: redisSession.ExpiresAt.Unix(),
	}, nil
}

func (r *RedisSessionRepository) UpdateSession(ctx context.Context, sessionID string, session *SessionData) error {
	redisSession := &redis.SessionData{
		UserID:    session.UserID,
		Roles:     session.Roles, // Now properly populated with user roles
		IPAddress: session.IPAddress,
		UserAgent: session.UserAgent,
		CreatedAt: time.Unix(session.CreatedAt, 0),
		LastUsed:  time.Unix(session.LastUsed, 0),
	}

	ttl := time.Unix(session.ExpiresAt, 0).Sub(time.Unix(session.CreatedAt, 0))
	return r.sessionStore.Update(ctx, sessionID, redisSession, ttl)
}

func (r *RedisSessionRepository) DeleteSession(ctx context.Context, sessionID string) error {
	return r.sessionStore.Delete(ctx, sessionID)
}

func (r *RedisSessionRepository) DeleteUserSessions(ctx context.Context, userID string) error {
	return r.sessionStore.DeleteUserSessions(ctx, userID)
}

func (r *RedisSessionRepository) GetUserSessions(ctx context.Context, userID string) ([]*SessionData, error) {
	redisSessions, err := r.sessionStore.GetUserSessions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user sessions: %w", err)
	}

	var sessions []*SessionData
	for _, redisSession := range redisSessions {
		sessions = append(sessions, &SessionData{
			UserID:    redisSession.UserID,
			IPAddress: redisSession.IPAddress,
			UserAgent: redisSession.UserAgent,
			CreatedAt: redisSession.CreatedAt.Unix(),
			LastUsed:  redisSession.LastUsed.Unix(),
			ExpiresAt: redisSession.ExpiresAt.Unix(),
		})
	}

	return sessions, nil
}

// RedisTokenBlacklistRepository adapts Redis token blacklist to TokenBlacklistRepository interface
type RedisTokenBlacklistRepository struct {
	blacklist *redis.TokenBlacklist
}

// NewRedisTokenBlacklistRepository creates a new Redis token blacklist repository
func NewRedisTokenBlacklistRepository(blacklist *redis.TokenBlacklist) TokenBlacklistRepository {
	return &RedisTokenBlacklistRepository{
		blacklist: blacklist,
	}
}

func (r *RedisTokenBlacklistRepository) BlacklistToken(ctx context.Context, tokenHash string, expiresAt int64, reason string) error {
	expiresAtTime := time.Unix(expiresAt, 0)
	return r.blacklist.BlacklistToken(ctx, tokenHash, "", expiresAtTime, reason, "access")
}

func (r *RedisTokenBlacklistRepository) IsTokenBlacklisted(ctx context.Context, tokenHash string) (bool, error) {
	isBlacklisted, _, err := r.blacklist.IsBlacklisted(ctx, tokenHash)
	return isBlacklisted, err
}

func (r *RedisTokenBlacklistRepository) BlacklistUserTokens(ctx context.Context, userID string, reason string) error {
	return r.blacklist.BlacklistUserTokens(ctx, userID, reason)
}
