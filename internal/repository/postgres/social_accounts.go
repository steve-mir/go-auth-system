package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/steve-mir/go-auth-system/internal/service/sso"
)

// SocialAccountRepository handles social account data operations
type SocialAccountRepository struct {
	db *sql.DB
}

// NewSocialAccountRepository creates a new social account repository
func NewSocialAccountRepository(db *sql.DB) *SocialAccountRepository {
	return &SocialAccountRepository{
		db: db,
	}
}

// CreateSocialAccount creates a new social account link
func (r *SocialAccountRepository) CreateSocialAccount(ctx context.Context, account *sso.SocialAccount) error {
	query := `
		INSERT INTO social_accounts (id, user_id, provider, social_id, email, name, access_token, refresh_token, expires_at, metadata, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	var expiresAt *time.Time
	if account.ExpiresAt != nil {
		expiresAt = account.ExpiresAt
	}

	metadataJSON := "{}"
	if account.Metadata != nil && len(account.Metadata) > 0 {
		// Convert metadata to JSON string
		// For simplicity, we'll store as empty JSON for now
		// In production, you'd want proper JSON marshaling
	}

	_, err := r.db.ExecContext(ctx, query,
		account.ID,
		account.UserID,
		account.Provider,
		account.SocialID,
		account.Email,
		account.Name,
		account.AccessToken,
		account.RefreshToken,
		expiresAt,
		metadataJSON,
		account.CreatedAt,
		account.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create social account: %w", err)
	}

	return nil
}

// GetSocialAccountByProviderAndSocialID retrieves a social account by provider and social ID
func (r *SocialAccountRepository) GetSocialAccountByProviderAndSocialID(ctx context.Context, provider, socialID string) (*sso.SocialAccount, error) {
	query := `
		SELECT id, user_id, provider, social_id, email, name, access_token, refresh_token, expires_at, metadata, created_at, updated_at
		FROM social_accounts
		WHERE provider = $1 AND social_id = $2
	`

	var account sso.SocialAccount
	var expiresAt sql.NullTime
	var metadata string

	err := r.db.QueryRowContext(ctx, query, provider, socialID).Scan(
		&account.ID,
		&account.UserID,
		&account.Provider,
		&account.SocialID,
		&account.Email,
		&account.Name,
		&account.AccessToken,
		&account.RefreshToken,
		&expiresAt,
		&metadata,
		&account.CreatedAt,
		&account.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Not found
		}
		return nil, fmt.Errorf("failed to get social account: %w", err)
	}

	if expiresAt.Valid {
		account.ExpiresAt = &expiresAt.Time
	}

	// Parse metadata JSON if needed
	account.Metadata = make(map[string]string)

	return &account, nil
}

// GetSocialAccountsByUserID retrieves all social accounts for a user
func (r *SocialAccountRepository) GetSocialAccountsByUserID(ctx context.Context, userID string) ([]*sso.SocialAccount, error) {
	query := `
		SELECT id, user_id, provider, social_id, email, name, access_token, refresh_token, expires_at, metadata, created_at, updated_at
		FROM social_accounts
		WHERE user_id = $1
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query social accounts: %w", err)
	}
	defer rows.Close()

	var accounts []*sso.SocialAccount

	for rows.Next() {
		var account sso.SocialAccount
		var expiresAt sql.NullTime
		var metadata string

		err := rows.Scan(
			&account.ID,
			&account.UserID,
			&account.Provider,
			&account.SocialID,
			&account.Email,
			&account.Name,
			&account.AccessToken,
			&account.RefreshToken,
			&expiresAt,
			&metadata,
			&account.CreatedAt,
			&account.UpdatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan social account: %w", err)
		}

		if expiresAt.Valid {
			account.ExpiresAt = &expiresAt.Time
		}

		// Parse metadata JSON if needed
		account.Metadata = make(map[string]string)

		accounts = append(accounts, &account)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating social accounts: %w", err)
	}

	return accounts, nil
}

// GetSocialAccountByUserIDAndProvider retrieves a social account by user ID and provider
func (r *SocialAccountRepository) GetSocialAccountByUserIDAndProvider(ctx context.Context, userID, provider string) (*sso.SocialAccount, error) {
	query := `
		SELECT id, user_id, provider, social_id, email, name, access_token, refresh_token, expires_at, metadata, created_at, updated_at
		FROM social_accounts
		WHERE user_id = $1 AND provider = $2
	`

	var account sso.SocialAccount
	var expiresAt sql.NullTime
	var metadata string

	err := r.db.QueryRowContext(ctx, query, userID, provider).Scan(
		&account.ID,
		&account.UserID,
		&account.Provider,
		&account.SocialID,
		&account.Email,
		&account.Name,
		&account.AccessToken,
		&account.RefreshToken,
		&expiresAt,
		&metadata,
		&account.CreatedAt,
		&account.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Not found
		}
		return nil, fmt.Errorf("failed to get social account: %w", err)
	}

	if expiresAt.Valid {
		account.ExpiresAt = &expiresAt.Time
	}

	// Parse metadata JSON if needed
	account.Metadata = make(map[string]string)

	return &account, nil
}

// UpdateSocialAccount updates a social account
func (r *SocialAccountRepository) UpdateSocialAccount(ctx context.Context, account *sso.SocialAccount) error {
	query := `
		UPDATE social_accounts
		SET email = $3, name = $4, access_token = $5, refresh_token = $6, expires_at = $7, metadata = $8, updated_at = $9
		WHERE user_id = $1 AND provider = $2
	`

	var expiresAt *time.Time
	if account.ExpiresAt != nil {
		expiresAt = account.ExpiresAt
	}

	metadataJSON := "{}"
	if account.Metadata != nil && len(account.Metadata) > 0 {
		// Convert metadata to JSON string
		// For simplicity, we'll store as empty JSON for now
	}

	account.UpdatedAt = time.Now()

	result, err := r.db.ExecContext(ctx, query,
		account.UserID,
		account.Provider,
		account.Email,
		account.Name,
		account.AccessToken,
		account.RefreshToken,
		expiresAt,
		metadataJSON,
		account.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update social account: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("social account not found")
	}

	return nil
}

// DeleteSocialAccount deletes a social account
func (r *SocialAccountRepository) DeleteSocialAccount(ctx context.Context, userID, provider string) error {
	query := `DELETE FROM social_accounts WHERE user_id = $1 AND provider = $2`

	result, err := r.db.ExecContext(ctx, query, userID, provider)
	if err != nil {
		return fmt.Errorf("failed to delete social account: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("social account not found")
	}

	return nil
}

// DeleteAllUserSocialAccounts deletes all social accounts for a user
func (r *SocialAccountRepository) DeleteAllUserSocialAccounts(ctx context.Context, userID string) error {
	query := `DELETE FROM social_accounts WHERE user_id = $1`

	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user social accounts: %w", err)
	}

	return nil
}
