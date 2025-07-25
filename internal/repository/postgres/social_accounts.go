package postgres

// import (
// 	"context"
// 	"encoding/json"
// 	"fmt"
// 	"time"

// 	"github.com/google/uuid"
// 	"github.com/jackc/pgx/v5/pgtype"
// 	"github.com/steve-mir/go-auth-system/internal/repository/postgres/db"
// 	"github.com/steve-mir/go-auth-system/internal/service/sso"
// )

// // SocialAccountRepository handles social account data operations using SQLC
// type SocialAccountRepository struct {
// 	queries *db.Queries
// }

// // NewSocialAccountRepository creates a new social account repository using SQLC
// func NewSocialAccountRepository(queries *db.Queries) *SocialAccountRepository {
// 	return &SocialAccountRepository{
// 		queries: queries,
// 	}
// }

// // CreateSocialAccount creates a new social account link
// func (r *SocialAccountRepository) CreateSocialAccount(ctx context.Context, account *sso.SocialAccount) error {
// 	var expiresAt pgtype.Timestamp
// 	if account.ExpiresAt != nil {
// 		expiresAt = pgtype.Timestamp{Time: *account.ExpiresAt, Valid: true}
// 	}

// 	metadataJSON, err := json.Marshal(account.Metadata)
// 	if err != nil {
// 		metadataJSON = []byte("{}")
// 	}

// 	accountId, _ := uuid.Parse(account.ID)
// 	params := db.CreateSocialAccountParams{
// 		ID:           accountId,
// 		UserID:       uuid.MustParse(account.UserID),
// 		Provider:     account.Provider,
// 		SocialID:     account.SocialID,
// 		Email:        pgtype.Text{String: account.Email, Valid: account.Email != ""},
// 		Name:         pgtype.Text{String: account.Name, Valid: account.Name != ""},
// 		AccessToken:  pgtype.Text{String: account.AccessToken, Valid: account.AccessToken != ""},
// 		RefreshToken: pgtype.Text{String: account.RefreshToken, Valid: account.RefreshToken != ""},
// 		ExpiresAt:    expiresAt,
// 		Metadata:     metadataJSON,
// 		CreatedAt:    pgtype.Timestamp{Time: account.CreatedAt, Valid: true},
// 		UpdatedAt:    pgtype.Timestamp{Time: account.UpdatedAt, Valid: true},
// 	}

// 	_, err = r.queries.CreateSocialAccount(ctx, params)
// 	if err != nil {
// 		return fmt.Errorf("failed to create social account: %w", err)
// 	}

// 	return nil
// }

// // GetSocialAccountByProviderAndSocialID retrieves a social account by provider and social ID
// func (r *SocialAccountRepository) GetSocialAccountByProviderAndSocialID(ctx context.Context, provider, socialID string) (*sso.SocialAccount, error) {
// 	params := db.GetSocialAccountByProviderAndSocialIDParams{
// 		Provider: provider,
// 		SocialID: socialID,
// 	}

// 	dbAccount, err := r.queries.GetSocialAccountByProviderAndSocialID(ctx, params)
// 	if err != nil {
// 		return nil, nil // Not found
// 	}

// 	return r.convertDBSocialAccountToSSO(&dbAccount)
// }

// // GetSocialAccountsByUserID retrieves all social accounts for a user
// func (r *SocialAccountRepository) GetSocialAccountsByUserID(ctx context.Context, userID string) ([]*sso.SocialAccount, error) {
// 	parsedUserID, err := uuid.Parse(userID)
// 	if err != nil {
// 		return nil, fmt.Errorf("invalid user ID: %w", err)
// 	}

// 	dbAccounts, err := r.queries.GetSocialAccountsByUserID(ctx, parsedUserID)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get social accounts: %w", err)
// 	}

// 	accounts := make([]*sso.SocialAccount, len(dbAccounts))
// 	for i, dbAccount := range dbAccounts {
// 		account, err := r.convertDBSocialAccountToSSO(&dbAccount)
// 		if err != nil {
// 			return nil, fmt.Errorf("failed to convert account %d: %w", i, err)
// 		}
// 		accounts[i] = account
// 	}

// 	return accounts, nil
// }

// // GetSocialAccountByUserIDAndProvider retrieves a social account by user ID and provider
// func (r *SocialAccountRepository) GetSocialAccountByUserIDAndProvider(ctx context.Context, userID, provider string) (*sso.SocialAccount, error) {
// 	parsedUserID, err := uuid.Parse(userID)
// 	if err != nil {
// 		return nil, fmt.Errorf("invalid user ID: %w", err)
// 	}

// 	params := db.GetSocialAccountByUserIDAndProviderParams{
// 		UserID:   parsedUserID,
// 		Provider: provider,
// 	}

// 	dbAccount, err := r.queries.GetSocialAccountByUserIDAndProvider(ctx, params)
// 	if err != nil {
// 		return nil, nil // Not found
// 	}

// 	return r.convertDBSocialAccountToSSO(&dbAccount)
// }

// // UpdateSocialAccount updates a social account
// func (r *SocialAccountRepository) UpdateSocialAccount(ctx context.Context, account *sso.SocialAccount) error {
// 	parsedUserID, err := uuid.Parse(account.UserID)
// 	if err != nil {
// 		return fmt.Errorf("invalid user ID: %w", err)
// 	}

// 	var expiresAt pgtype.Timestamp
// 	if account.ExpiresAt != nil {
// 		expiresAt = pgtype.Timestamp{Time: *account.ExpiresAt, Valid: true}
// 	}

// 	metadataJSON, err := json.Marshal(account.Metadata)
// 	if err != nil {
// 		metadataJSON = []byte("{}")
// 	}

// 	account.UpdatedAt = time.Now()

// 	params := db.UpdateSocialAccountParams{
// 		UserID:       parsedUserID,
// 		Provider:     account.Provider,
// 		Email:        pgtype.Text{String: account.Email, Valid: account.Email != ""},
// 		Name:         pgtype.Text{String: account.Name, Valid: account.Name != ""},
// 		AccessToken:  pgtype.Text{String: account.AccessToken, Valid: account.AccessToken != ""},
// 		RefreshToken: pgtype.Text{String: account.RefreshToken, Valid: account.RefreshToken != ""},
// 		ExpiresAt:    expiresAt,
// 		Metadata:     metadataJSON,
// 		UpdatedAt:    pgtype.Timestamp{Time: account.UpdatedAt, Valid: true},
// 	}

// 	err = r.queries.UpdateSocialAccount(ctx, params)
// 	if err != nil {
// 		return fmt.Errorf("failed to update social account: %w", err)
// 	}

// 	return nil
// }

// // DeleteSocialAccount deletes a social account
// func (r *SocialAccountRepository) DeleteSocialAccount(ctx context.Context, userID, provider string) error {
// 	parsedUserID, err := uuid.Parse(userID)
// 	if err != nil {
// 		return fmt.Errorf("invalid user ID: %w", err)
// 	}

// 	params := db.DeleteSocialAccountParams{
// 		UserID:   parsedUserID,
// 		Provider: provider,
// 	}

// 	err = r.queries.DeleteSocialAccount(ctx, params)
// 	if err != nil {
// 		return fmt.Errorf("failed to delete social account: %w", err)
// 	}

// 	return nil
// }

// // DeleteAllUserSocialAccounts deletes all social accounts for a user
// func (r *SocialAccountRepository) DeleteAllUserSocialAccounts(ctx context.Context, userID string) error {
// 	parsedUserID, err := uuid.Parse(userID)
// 	if err != nil {
// 		return fmt.Errorf("invalid user ID: %w", err)
// 	}

// 	err = r.queries.DeleteAllUserSocialAccounts(ctx, parsedUserID)
// 	if err != nil {
// 		return fmt.Errorf("failed to delete user social accounts: %w", err)
// 	}

// 	return nil
// }

// // convertDBSocialAccountToSSO converts a database social account to SSO social account
// func (r *SocialAccountRepository) convertDBSocialAccountToSSO(dbAccount *db.SocialAccount) (*sso.SocialAccount, error) {
// 	account := &sso.SocialAccount{
// 		ID:       dbAccount.ID.String(),
// 		UserID:   dbAccount.UserID.String(),
// 		Provider: dbAccount.Provider,
// 		SocialID: dbAccount.SocialID,
// 	}

// 	if dbAccount.Email.Valid {
// 		account.Email = dbAccount.Email.String
// 	}

// 	if dbAccount.Name.Valid {
// 		account.Name = dbAccount.Name.String
// 	}

// 	if dbAccount.AccessToken.Valid {
// 		account.AccessToken = dbAccount.AccessToken.String
// 	}

// 	if dbAccount.RefreshToken.Valid {
// 		account.RefreshToken = dbAccount.RefreshToken.String
// 	}

// 	if dbAccount.ExpiresAt.Valid {
// 		account.ExpiresAt = &dbAccount.ExpiresAt.Time
// 	}

// 	if dbAccount.CreatedAt.Valid {
// 		account.CreatedAt = dbAccount.CreatedAt.Time
// 	}

// 	if dbAccount.UpdatedAt.Valid {
// 		account.UpdatedAt = dbAccount.UpdatedAt.Time
// 	}

// 	// Parse metadata
// 	account.Metadata = make(map[string]string)
// 	if len(dbAccount.Metadata) > 0 {
// 		var metadata map[string]string
// 		if err := json.Unmarshal(dbAccount.Metadata, &metadata); err == nil {
// 			account.Metadata = metadata
// 		}
// 	}

// 	return account, nil
// }
