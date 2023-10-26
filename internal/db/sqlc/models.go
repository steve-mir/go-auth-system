// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.22.0

package sqlc

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/sqlc-dev/pqtype"
)

type BannedUser struct {
	ID       int32          `json:"id"`
	UserID   uuid.UUID      `json:"user_id"`
	BannedAt sql.NullTime   `json:"banned_at"`
	Reason   sql.NullString `json:"reason"`
}

type EmailVerificationRequest struct {
	ID         int64        `json:"id"`
	UserID     uuid.UUID    `json:"user_id"`
	Email      string       `json:"email"`
	Token      string       `json:"token"`
	IsVerified sql.NullBool `json:"is_verified"`
	CreatedAt  sql.NullTime `json:"created_at"`
	ExpiresAt  time.Time    `json:"expires_at"`
}

type LoginFailure struct {
	ID        int32          `json:"id"`
	Email     string         `json:"email"`
	Timestamp sql.NullTime   `json:"timestamp"`
	UserAgent sql.NullString `json:"user_agent"`
	IpAddress pqtype.Inet    `json:"ip_address"`
}

type Role struct {
	ID   int32          `json:"id"`
	Name sql.NullString `json:"name"`
}

type SecurityQuestion struct {
	ID        int32          `json:"id"`
	UserID    uuid.UUID      `json:"user_id"`
	Question  sql.NullString `json:"question"`
	Answer    sql.NullString `json:"answer"`
	ExpiredAt sql.NullTime   `json:"expired_at"`
}

type Session struct {
	ID           uuid.UUID      `json:"id"`
	UserID       uuid.UUID      `json:"user_id"`
	Email        sql.NullString `json:"email"`
	RefreshToken string         `json:"refresh_token"`
	UserAgent    string         `json:"user_agent"`
	IpAddress    pqtype.Inet    `json:"ip_address"`
	IsBlocked    bool           `json:"is_blocked"`
	IsBreached   bool           `json:"is_breached"`
	ExpiresAt    time.Time      `json:"expires_at"`
	CreatedAt    sql.NullTime   `json:"created_at"`
	LastActiveAt sql.NullTime   `json:"last_active_at"`
}

type User struct {
	ID                uuid.UUID      `json:"id"`
	Name              sql.NullString `json:"name"`
	Email             string         `json:"email"`
	Username          sql.NullString `json:"username"`
	PasswordHash      string         `json:"password_hash"`
	CreatedAt         sql.NullTime   `json:"created_at"`
	UpdatedAt         sql.NullTime   `json:"updated_at"`
	IsSuspended       sql.NullBool   `json:"is_suspended"`
	IsVerified        sql.NullBool   `json:"is_verified"`
	IsEmailVerified   sql.NullBool   `json:"is_email_verified"`
	IsDeleted         bool           `json:"is_deleted"`
	LoginAttempts     sql.NullInt32  `json:"login_attempts"`
	LockoutDuration   sql.NullInt32  `json:"lockout_duration"`
	LockoutUntil      sql.NullTime   `json:"lockout_until"`
	PasswordChangedAt sql.NullTime   `json:"password_changed_at"`
	DeletedAt         sql.NullTime   `json:"deleted_at"`
	SuspendedAt       sql.NullTime   `json:"suspended_at"`
	EmailVerifiedAt   sql.NullTime   `json:"email_verified_at"`
}

type UserLogin struct {
	ID        int32          `json:"id"`
	UserID    uuid.UUID      `json:"user_id"`
	LoginAt   sql.NullTime   `json:"login_at"`
	IpAddress pqtype.Inet    `json:"ip_address"`
	UserAgent sql.NullString `json:"user_agent"`
}

type UserPreference struct {
	UserID      uuid.NullUUID         `json:"user_id"`
	Preferences pqtype.NullRawMessage `json:"preferences"`
}

type UserProfile struct {
	ID        int32          `json:"id"`
	UserID    uuid.NullUUID  `json:"user_id"`
	FirstName sql.NullString `json:"first_name"`
	LastName  sql.NullString `json:"last_name"`
	Phone     sql.NullString `json:"phone"`
}

type UserRole struct {
	ID     int32         `json:"id"`
	UserID uuid.NullUUID `json:"user_id"`
	RoleID sql.NullInt32 `json:"role_id"`
}
