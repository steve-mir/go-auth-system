package sso

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/steve-mir/go-auth-system/internal/interfaces"
	"github.com/steve-mir/go-auth-system/internal/repository/postgres"
	"github.com/steve-mir/go-auth-system/internal/repository/postgres/db"
	"github.com/steve-mir/go-auth-system/internal/security/crypto"
	"github.com/steve-mir/go-auth-system/internal/service/auth"
)

type SocialAccountData struct {
	ID              string `json:"id"`
	UserID          string `json:"user_id"`
	Provider        string `json:"provider"`
	ProviderUserID  string `json:"provider_user_id"`
	Email           string `json:"email"`
	Name            string `json:"name"`
	AvatarURL       string `json:"avatar_url"`
	AccessToken     string `json:"access_token"`
	RefreshToken    string `json:"refresh_token"`
	ProfileData     string `json:"profile_data"`
	IsEmailVerified bool   `json:"is_email_verified"`
}

// PostgresSocialAccountRepository implements the SocialAccountRepository interface using PostgreSQL
type PostgresSocialAccountRepository struct {
	db    *postgres.DB
	store *db.Store
}

// NewPostgresSocialAccountRepository creates a new PostgreSQL social account repository
func NewPostgresSocialAccountRepository(db *postgres.DB, store *db.Store) SocialAccountRepository {
	return &PostgresSocialAccountRepository{
		db:    db,
		store: store,
	}
}

// CreateSocialAccount creates a new social account
func (r *PostgresSocialAccountRepository) CreateSocialAccount(ctx context.Context, account *SocialAccount) error {
	userID, err := uuid.Parse(account.UserID)
	if err != nil {
		return err
	}

	params := db.CreateSocialAccountParams{
		ID:           uuid.New(),
		UserID:       userID,
		Provider:     account.Provider,
		Email:        pgtype.Text{String: account.Email, Valid: account.Email != ""},
		Name:         pgtype.Text{String: account.Name, Valid: account.Name != ""},
		AccessToken:  pgtype.Text{String: account.AccessToken, Valid: account.AccessToken != ""},
		RefreshToken: pgtype.Text{String: account.RefreshToken, Valid: account.RefreshToken != ""},
		// ProviderUserID:  account.ProviderUserID,
		// AvatarURL:       pgtype.Text{String: account.AvatarURL, Valid: account.AvatarURL != ""},
		// TokenExpiresAt:  pgtype.Timestamptz{Time: time.Unix(account.TokenExpiresAt, 0), Valid: account.TokenExpiresAt > 0},
		// ProfileData:     account.ProfileData,
		// IsEmailVerified: account.IsEmailVerified,
		// LastLoginAt:     pgtype.Timestamptz{Time: time.Unix(account.LastLoginAt, 0), Valid: account.LastLoginAt > 0},
	}

	_, err = r.store.CreateSocialAccount(ctx, params)
	return err
}

// GetSocialAccountByProvider retrieves a social account by provider and provider user ID
func (r *PostgresSocialAccountRepository) GetSocialAccountByProvider(ctx context.Context, provider, providerUserID string) (*SocialAccountData, error) {
	return nil, nil
	// TODO: Implement in sqlc
	// dbAccount, err := r.store.GetSocialAccountByProvider(ctx, db.GetSocialAccountByProviderParams{
	// 	Provider:       provider,
	// 	ProviderUserID: providerUserID,
	// })
	// if err != nil {
	// 	if err == sql.ErrNoRows {
	// 		return nil, nil
	// 	}
	// 	return nil, err
	// }

	// return r.dbSocialAccountToSocialAccount(dbAccount), nil
}

func (r *PostgresSocialAccountRepository) DeleteAllUserSocialAccounts(ctx context.Context, userID string) error {
	// TODO:  Implement
	return nil
}

func (r *PostgresSocialAccountRepository) GetSocialAccountByProviderAndSocialID(ctx context.Context, provider, socialID string) (*SocialAccount, error) {
	// TODO: implement
	return nil, nil
}

// GetSocialAccountsByUserID retrieves all social accounts for a user
func (r *PostgresSocialAccountRepository) GetSocialAccountsByUserID(ctx context.Context, userID string) ([]*SocialAccount, error) {
	// TODO: Implement
	return nil, nil
}

// GetSocialAccountByUserIDAndProvider retrieves a social account by user ID and provider
func (r *PostgresSocialAccountRepository) GetSocialAccountByUserIDAndProvider(ctx context.Context, userID, provider string) (*SocialAccount, error) {
	// TODO: Implement
	return nil, nil
}

// GetUserSocialAccounts retrieves all social accounts for a user
func (r *PostgresSocialAccountRepository) GetUserSocialAccounts(ctx context.Context, userID string) ([]*SocialAccountData, error) {

	return nil, nil
	// TODO:  Implement
	// userUUID, err := uuid.Parse(userID)
	// if err != nil {
	// 	return nil, err
	// }

	// dbAccounts, err := r.store.GetUserSocialAccounts(ctx, userUUID)
	// if err != nil {
	// 	return nil, err
	// }

	// accounts := make([]*SocialAccountData, len(dbAccounts))
	// for i, dbAccount := range dbAccounts {
	// 	accounts[i] = r.dbSocialAccountToSocialAccount(dbAccount)
	// }

	// return accounts, nil
}

// UpdateSocialAccount updates a social account
func (r *PostgresSocialAccountRepository) UpdateSocialAccount(ctx context.Context, account *SocialAccount) error {
	accountID, err := uuid.Parse(account.ID)
	if err != nil {
		return err
	}

	params := db.UpdateSocialAccountParams{
		// AvatarURL:       pgtype.Text{String: account.AvatarURL, Valid: account.AvatarURL != ""},
		UserID:       accountID,
		Provider:     account.Provider,
		Email:        pgtype.Text{String: account.Email, Valid: account.Email != ""},
		Name:         pgtype.Text{String: account.Name, Valid: account.Name != ""},
		AccessToken:  pgtype.Text{String: account.AccessToken, Valid: account.AccessToken != ""},
		RefreshToken: pgtype.Text{String: account.RefreshToken, Valid: account.RefreshToken != ""},
		// ExpiresAt:  pgtype.Timestamptz{Time: time.Unix(account.TokenExpiresAt, 0), Valid: account.TokenExpiresAt > 0},
		// ProfileData:     account.ProfileData,
		// IsEmailVerified: account.IsEmailVerified,
		// LastLoginAt:     pgtype.Timestamptz{Time: time.Unix(account.LastLoginAt, 0), Valid: account.LastLoginAt > 0},
	}

	err = r.store.UpdateSocialAccount(ctx, params)
	return err
}

// DeleteSocialAccount deletes a social account
func (r *PostgresSocialAccountRepository) DeleteSocialAccount(ctx context.Context, accountID string, provider string) error {
	id, err := uuid.Parse(accountID)
	if err != nil {
		return err
	}

	return r.store.DeleteSocialAccount(ctx, db.DeleteSocialAccountParams{
		UserID:   id,
		Provider: provider,
	})
}

// dbSocialAccountToSocialAccount converts a database social account to a service social account
func (r *PostgresSocialAccountRepository) dbSocialAccountToSocialAccount(dbAccount db.SocialAccount) *SocialAccountData {
	account := &SocialAccountData{
		ID:             dbAccount.ID.String(),
		UserID:         dbAccount.UserID.String(),
		Provider:       dbAccount.Provider,
		ProviderUserID: dbAccount.UserID.String(),
		Email:          dbAccount.Email.String,
		Name:           dbAccount.Name.String,
		RefreshToken:   dbAccount.RefreshToken.String,
		AccessToken:    dbAccount.AccessToken.String,
		// CreatedAt:       dbAccount.CreatedAt.Time.Unix(),
		// UpdatedAt:       dbAccount.UpdatedAt.Time.Unix(),
		// AvatarURL:       dbAccount.AvatarURL.String,
		// ProfileData:     dbAccount.ProfileData,
		// IsEmailVerified: dbAccount.IsEmailVerified,
	}

	// if dbAccount.TokenExpiresAt.Valid {
	// 	account.TokenExpiresAt = dbAccount.TokenExpiresAt.Time.Unix()
	// }

	// if dbAccount.LastLoginAt.Valid {
	// 	account.LastLoginAt = dbAccount.LastLoginAt.Time.Unix()
	// }

	return account
}

// // RedisStateStore implements the StateStore interface using Redis
// type RedisStateStore struct {
// 	client *redis.Client
// }

// // NewRedisStateStore creates a new Redis state store
// func NewRedisStateStore(client *redis.Client) StateStore {
// 	return &RedisStateStore{
// 		client: client,
// 	}
// }

// StoreState stores OAuth state with expiration
// func (r *RedisStateStore) StoreState(ctx context.Context, stateKey string, state *OAuthState) error {
// 	data, err := json.Marshal(state)
// 	if err != nil {
// 		return err
// 	}

// 	// Store for 10 minutes
// 	return r.client.Set(ctx, "oauth_state:"+stateKey, data, 600).Err()
// }

// GetState retrieves OAuth state
// func (r *RedisStateStore) GetState(ctx context.Context, stateKey string) (*OAuthState, error) {
// 	return nil, nil

// 	// data, err := r.client.Get(ctx, "oauth_state:"+stateKey)//.Result()
// 	// if err != nil {
// 	// 	return nil, err
// 	// }

// 	// var state OAuthState
// 	// if err := json.Unmarshal(data, &state); err != nil {
// 	// 	return nil, err
// 	// }

// 	// return &state, nil
// }

// // DeleteState removes OAuth state
// func (r *RedisStateStore) DeleteState(ctx context.Context, stateKey string) error {
// 	return r.client.Del(ctx, "oauth_state:"+stateKey).Err()
// }

// SSOUserRepositoryAdapter adapts auth.UserRepository to sso.UserRepository interface
type SSOUserRepositoryAdapter struct {
	authRepo  auth.UserRepository
	encryptor crypto.Encryptor
}

// NewSSOUserRepositoryAdapter creates a new SSO user repository adapter
func NewSSOUserRepositoryAdapter(authRepo auth.UserRepository, encryptor crypto.Encryptor) UserRepository {
	return &SSOUserRepositoryAdapter{
		authRepo:  authRepo,
		encryptor: encryptor,
	}
}

// GetUserByEmail retrieves a user by email
func (a *SSOUserRepositoryAdapter) GetUserByEmail(ctx context.Context, email string) (*UserData, error) {
	authUser, err := a.authRepo.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	return &UserData{
		ID:                 authUser.ID,
		Email:              authUser.Email,
		Username:           authUser.Username,
		PasswordHash:       authUser.PasswordHash,
		HashAlgorithm:      authUser.HashAlgorithm,
		FirstNameEncrypted: authUser.FirstNameEncrypted,
		LastNameEncrypted:  authUser.LastNameEncrypted,
		PhoneEncrypted:     authUser.PhoneEncrypted,
		EmailVerified:      authUser.EmailVerified,
		PhoneVerified:      authUser.PhoneVerified,
		AccountLocked:      authUser.AccountLocked,
		FailedAttempts:     authUser.FailedAttempts,
		LastLoginAt:        authUser.LastLoginAt,
		CreatedAt:          authUser.CreatedAt,
		UpdatedAt:          authUser.UpdatedAt,
	}, nil
}

// CreateUser creates a new user
func (a *SSOUserRepositoryAdapter) CreateUser(ctx context.Context, user *CreateUserData) (*UserData, error) {
	// Encrypt sensitive data
	var firstNameEncrypted, lastNameEncrypted, phoneEncrypted []byte
	var err error

	if user.FirstName != "" {
		firstNameEncrypted, err = a.encryptor.Encrypt([]byte(user.FirstName))
		if err != nil {
			return nil, err
		}
	}

	if user.LastName != "" {
		lastNameEncrypted, err = a.encryptor.Encrypt([]byte(user.LastName))
		if err != nil {
			return nil, err
		}
	}

	if user.Phone != "" {
		phoneEncrypted, err = a.encryptor.Encrypt([]byte(user.Phone))
		if err != nil {
			return nil, err
		}
	}

	authUser := &interfaces.CreateUserData{
		Email:              user.Email,
		Username:           user.Username,
		PasswordHash:       user.PasswordHash,
		HashAlgorithm:      user.HashAlgorithm,
		FirstNameEncrypted: firstNameEncrypted,
		LastNameEncrypted:  lastNameEncrypted,
		PhoneEncrypted:     phoneEncrypted,
	}

	createdUser, err := a.authRepo.CreateUser(ctx, authUser)
	if err != nil {
		return nil, err
	}

	return &UserData{
		ID:                 createdUser.ID,
		Email:              createdUser.Email,
		Username:           createdUser.Username,
		PasswordHash:       createdUser.PasswordHash,
		HashAlgorithm:      createdUser.HashAlgorithm,
		FirstNameEncrypted: createdUser.FirstNameEncrypted,
		LastNameEncrypted:  createdUser.LastNameEncrypted,
		PhoneEncrypted:     createdUser.PhoneEncrypted,
		EmailVerified:      createdUser.EmailVerified,
		PhoneVerified:      createdUser.PhoneVerified,
		AccountLocked:      createdUser.AccountLocked,
		FailedAttempts:     createdUser.FailedAttempts,
		LastLoginAt:        createdUser.LastLoginAt,
		CreatedAt:          createdUser.CreatedAt,
		UpdatedAt:          createdUser.UpdatedAt,
	}, nil
}

// UpdateUser updates a user
func (a *SSOUserRepositoryAdapter) UpdateUser(ctx context.Context, user *UpdateUserData) error {
	// Encrypt sensitive data if provided
	var firstNameEncrypted, lastNameEncrypted, phoneEncrypted []byte
	var err error

	if user.FirstName != "" {
		firstNameEncrypted, err = a.encryptor.Encrypt([]byte(user.FirstName))
		if err != nil {
			return err
		}
	}

	if user.LastName != "" {
		lastNameEncrypted, err = a.encryptor.Encrypt([]byte(user.LastName))
		if err != nil {
			return err
		}
	}

	if user.Phone != "" {
		phoneEncrypted, err = a.encryptor.Encrypt([]byte(user.Phone))
		if err != nil {
			return err
		}
	}

	authUser := &interfaces.UpdateUserData{
		ID:                 user.ID,
		Username:           user.Username,
		FirstNameEncrypted: firstNameEncrypted,
		LastNameEncrypted:  lastNameEncrypted,
		PhoneEncrypted:     phoneEncrypted,
	}

	return a.authRepo.UpdateUser(ctx, authUser)
}
