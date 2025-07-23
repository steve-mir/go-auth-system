package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/steve-mir/go-auth-system/internal/service/admin"
)

// AdminSessionRepository implements the admin.SessionRepository interface
type AdminSessionRepository struct {
	db *sql.DB
}

// NewAdminSessionRepository creates a new admin session repository
func NewAdminSessionRepository(db *sql.DB) *AdminSessionRepository {
	return &AdminSessionRepository{
		db: db,
	}
}

// GetAllSessions retrieves all user sessions with pagination and filtering
func (r *AdminSessionRepository) GetAllSessions(ctx context.Context, req *admin.GetSessionsRequest) ([]admin.UserSession, int64, error) {
	// Build the base query
	baseQuery := `
		SELECT 
			s.id, s.user_id, u.email, s.ip_address, s.user_agent,
			s.created_at, s.last_used_at, s.expires_at, s.token_type,
			CASE WHEN s.expires_at > NOW() THEN true ELSE false END as is_active
		FROM user_sessions s
		JOIN users u ON s.user_id = u.id
	`

	countQuery := `
		SELECT COUNT(*)
		FROM user_sessions s
		JOIN users u ON s.user_id = u.id
	`

	var conditions []string
	var args []interface{}
	argIndex := 1

	// Add filters
	if req.UserID != "" {
		userUUID, err := uuid.Parse(req.UserID)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid user ID: %w", err)
		}
		conditions = append(conditions, fmt.Sprintf("s.user_id = $%d", argIndex))
		args = append(args, userUUID)
		argIndex++
	}

	// Add WHERE clause if conditions exist
	if len(conditions) > 0 {
		whereClause := " WHERE " + strings.Join(conditions, " AND ")
		baseQuery += whereClause
		countQuery += whereClause
	}

	// Get total count
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get sessions count: %w", err)
	}

	// Add sorting
	sortBy := "created_at"
	if req.SortBy != "" {
		switch req.SortBy {
		case "created_at", "last_used_at", "expires_at", "user_email":
			sortBy = req.SortBy
		}
	}

	sortOrder := "DESC"
	if req.SortOrder == "asc" {
		sortOrder = "ASC"
	}

	baseQuery += fmt.Sprintf(" ORDER BY %s %s", sortBy, sortOrder)

	// Add pagination
	offset := (req.Page - 1) * req.Limit
	baseQuery += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIndex, argIndex+1)
	args = append(args, req.Limit, offset)

	// Execute query
	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query sessions: %w", err)
	}
	defer rows.Close()

	var sessions []admin.UserSession
	for rows.Next() {
		var session admin.UserSession
		err := rows.Scan(
			&session.SessionID,
			&session.UserID,
			&session.UserEmail,
			&session.IPAddress,
			&session.UserAgent,
			&session.CreatedAt,
			&session.LastUsed,
			&session.ExpiresAt,
			&session.TokenType,
			&session.IsActive,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan session: %w", err)
		}
		sessions = append(sessions, session)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating sessions: %w", err)
	}

	return sessions, total, nil
}

// DeleteSession deletes a specific session
func (r *AdminSessionRepository) DeleteSession(ctx context.Context, sessionID uuid.UUID) error {
	query := `DELETE FROM user_sessions WHERE id = $1`
	result, err := r.db.ExecContext(ctx, query, sessionID)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("session not found")
	}

	return nil
}

// GetSessionByID retrieves a session by ID
func (r *AdminSessionRepository) GetSessionByID(ctx context.Context, sessionID uuid.UUID) (*admin.UserSession, error) {
	query := `
		SELECT 
			s.id, s.user_id, u.email, s.ip_address, s.user_agent,
			s.created_at, s.last_used_at, s.expires_at, s.token_type,
			CASE WHEN s.expires_at > NOW() THEN true ELSE false END as is_active
		FROM user_sessions s
		JOIN users u ON s.user_id = u.id
		WHERE s.id = $1
	`

	var session admin.UserSession
	err := r.db.QueryRowContext(ctx, query, sessionID).Scan(
		&session.SessionID,
		&session.UserID,
		&session.UserEmail,
		&session.IPAddress,
		&session.UserAgent,
		&session.CreatedAt,
		&session.LastUsed,
		&session.ExpiresAt,
		&session.TokenType,
		&session.IsActive,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("session not found")
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	return &session, nil
}

// GetUserSessions retrieves sessions for a specific user
func (r *AdminSessionRepository) GetUserSessions(ctx context.Context, userID uuid.UUID) ([]admin.UserSession, error) {
	query := `
		SELECT 
			s.id, s.user_id, u.email, s.ip_address, s.user_agent,
			s.created_at, s.last_used_at, s.expires_at, s.token_type,
			CASE WHEN s.expires_at > NOW() THEN true ELSE false END as is_active
		FROM user_sessions s
		JOIN users u ON s.user_id = u.id
		WHERE s.user_id = $1
		ORDER BY s.created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query user sessions: %w", err)
	}
	defer rows.Close()

	var sessions []admin.UserSession
	for rows.Next() {
		var session admin.UserSession
		err := rows.Scan(
			&session.SessionID,
			&session.UserID,
			&session.UserEmail,
			&session.IPAddress,
			&session.UserAgent,
			&session.CreatedAt,
			&session.LastUsed,
			&session.ExpiresAt,
			&session.TokenType,
			&session.IsActive,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan session: %w", err)
		}
		sessions = append(sessions, session)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating sessions: %w", err)
	}

	return sessions, nil
}

// DeleteUserSessions deletes all sessions for a user
func (r *AdminSessionRepository) DeleteUserSessions(ctx context.Context, userID uuid.UUID) error {
	query := `DELETE FROM user_sessions WHERE user_id = $1`
	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user sessions: %w", err)
	}
	return nil
}

// GetActiveSessionsCount returns the count of active sessions
func (r *AdminSessionRepository) GetActiveSessionsCount(ctx context.Context) (int64, error) {
	query := `SELECT COUNT(*) FROM user_sessions WHERE expires_at > NOW()`
	var count int64
	err := r.db.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to get active sessions count: %w", err)
	}
	return count, nil
}

// CleanupExpiredSessions removes expired sessions
func (r *AdminSessionRepository) CleanupExpiredSessions(ctx context.Context) error {
	query := `DELETE FROM user_sessions WHERE expires_at <= NOW()`
	result, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	// Log the number of cleaned up sessions (could be useful for monitoring)
	_ = rowsAffected

	return nil
}
