package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/steve-mir/go-auth-system/internal/interfaces"
	"github.com/steve-mir/go-auth-system/internal/repository/postgres/db"
)

// AdminSessionRepository implements the interfaces.SessionRepository interface using SQLC
type AdminSessionRepository struct {
	queries *db.Queries
}

// NewAdminSessionRepository creates a new admin session repository using SQLC
func NewAdminSessionRepository(queries *db.Queries) *AdminSessionRepository {
	return &AdminSessionRepository{
		queries: queries,
	}
}

// GetAllSessions retrieves all user sessions with pagination and filtering
func (r *AdminSessionRepository) GetAllSessions(ctx context.Context, req *interfaces.GetSessionsRequest) ([]interfaces.UserSession, int64, error) {
	// Parse user ID if provided
	var userUUID pgtype.UUID
	if req.UserID != "" {
		parsedUUID, err := uuid.Parse(req.UserID)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid user ID: %w", err)
		}
		userUUID = pgtype.UUID{Bytes: parsedUUID, Valid: true}
	}

	// Get total count
	total, err := r.queries.CountAllSessions(ctx, userUUID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get sessions count: %w", err)
	}

	// Get sessions
	offset := (req.Page - 1) * req.Limit
	params := db.GetAllSessionsParams{
		Column1: userUUID,
		Column2: req.SortBy,
		Limit:   int32(req.Limit),
		Offset:  int32(offset),
	}

	dbSessions, err := r.queries.GetAllSessions(ctx, params)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get sessions: %w", err)
	}

	sessions := make([]interfaces.UserSession, len(dbSessions))
	for i, dbSession := range dbSessions {
		sessions[i] = r.convertDBSessionToAdmin(&dbSession)
	}

	return sessions, total, nil
}

// DeleteSession deletes a specific session
func (r *AdminSessionRepository) DeleteSession(ctx context.Context, sessionID uuid.UUID) error {
	err := r.queries.DeleteSession(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

// GetSessionByID retrieves a session by ID
func (r *AdminSessionRepository) GetSessionByID(ctx context.Context, sessionID uuid.UUID) (*interfaces.UserSession, error) {
	dbSession, err := r.queries.GetSessionByID(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	session := r.convertGetSessionByIDRowToAdmin(&dbSession)
	return &session, nil
}

// GetUserSessions retrieves sessions for a specific user
func (r *AdminSessionRepository) GetUserSessions(ctx context.Context, userID uuid.UUID) ([]interfaces.UserSession, error) {
	params := db.GetUserSessionsParams{
		UserID: userID,
		Limit:  100, // Default limit
		Offset: 0,
	}

	dbSessions, err := r.queries.GetUserSessions(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to get user sessions: %w", err)
	}

	sessions := make([]interfaces.UserSession, len(dbSessions))
	for i, dbSession := range dbSessions {
		sessions[i] = r.convertGetUserSessionsRowToAdmin(&dbSession)
	}

	return sessions, nil
}

// DeleteUserSessions deletes all sessions for a user
func (r *AdminSessionRepository) DeleteUserSessions(ctx context.Context, userID uuid.UUID) error {
	err := r.queries.DeleteUserSessions(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user sessions: %w", err)
	}
	return nil
}

// GetActiveSessionsCount returns the count of active sessions
func (r *AdminSessionRepository) GetActiveSessionsCount(ctx context.Context) (int64, error) {
	count, err := r.queries.GetActiveSessionsCount(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get active sessions count: %w", err)
	}
	return count, nil
}

// CleanupExpiredSessions removes expired sessions
func (r *AdminSessionRepository) CleanupExpiredSessions(ctx context.Context) error {
	err := r.queries.CleanupExpiredSessions(ctx)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}
	return nil
}

// convertDBSessionToAdmin converts a database session to admin session
func (r *AdminSessionRepository) convertDBSessionToAdmin(dbSession *db.GetAllSessionsRow) interfaces.UserSession {
	session := interfaces.UserSession{
		SessionID: dbSession.ID,
		UserID:    dbSession.UserID,
		UserEmail: dbSession.Email,
		TokenType: dbSession.TokenType,
		IsActive:  dbSession.IsActive,
	}

	if dbSession.IpAddress != nil {
		session.IPAddress = dbSession.IpAddress.String()
	}

	if dbSession.UserAgent.Valid {
		session.UserAgent = dbSession.UserAgent.String
	}

	if dbSession.CreatedAt.Valid {
		session.CreatedAt = dbSession.CreatedAt.Time
	}

	if dbSession.LastUsedAt.Valid {
		session.LastUsed = dbSession.LastUsedAt.Time
	}

	if dbSession.ExpiresAt.Valid {
		session.ExpiresAt = dbSession.ExpiresAt.Time
	}

	return session
}

// convertGetSessionByIDRowToAdmin converts a GetSessionByIDRow to admin session
func (r *AdminSessionRepository) convertGetSessionByIDRowToAdmin(dbSession *db.GetSessionByIDRow) interfaces.UserSession {
	session := interfaces.UserSession{
		SessionID: dbSession.ID,
		UserID:    dbSession.UserID,
		UserEmail: dbSession.Email,
		TokenType: dbSession.TokenType,
		IsActive:  dbSession.IsActive,
	}

	if dbSession.IpAddress != nil {
		session.IPAddress = dbSession.IpAddress.String()
	}

	if dbSession.UserAgent.Valid {
		session.UserAgent = dbSession.UserAgent.String
	}

	if dbSession.CreatedAt.Valid {
		session.CreatedAt = dbSession.CreatedAt.Time
	}

	if dbSession.LastUsedAt.Valid {
		session.LastUsed = dbSession.LastUsedAt.Time
	}

	if dbSession.ExpiresAt.Valid {
		session.ExpiresAt = dbSession.ExpiresAt.Time
	}

	return session
}

// convertGetUserSessionsRowToAdmin converts a GetUserSessionsRow to admin session
func (r *AdminSessionRepository) convertGetUserSessionsRowToAdmin(dbSession *db.GetUserSessionsRow) interfaces.UserSession {
	session := interfaces.UserSession{
		SessionID: dbSession.ID,
		UserID:    dbSession.UserID,
		UserEmail: dbSession.Email,
		TokenType: dbSession.TokenType,
		IsActive:  dbSession.IsActive,
	}

	if dbSession.IpAddress != nil {
		session.IPAddress = dbSession.IpAddress.String()
	}

	if dbSession.UserAgent.Valid {
		session.UserAgent = dbSession.UserAgent.String
	}

	if dbSession.CreatedAt.Valid {
		session.CreatedAt = dbSession.CreatedAt.Time
	}

	if dbSession.LastUsedAt.Valid {
		session.LastUsed = dbSession.LastUsedAt.Time
	}

	if dbSession.ExpiresAt.Valid {
		session.ExpiresAt = dbSession.ExpiresAt.Time
	}

	return session
}
