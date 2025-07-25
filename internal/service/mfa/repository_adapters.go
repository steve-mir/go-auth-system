package mfa

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/steve-mir/go-auth-system/internal/interfaces"
	"github.com/steve-mir/go-auth-system/internal/repository/postgres"
	"github.com/steve-mir/go-auth-system/internal/repository/postgres/db"
	"github.com/steve-mir/go-auth-system/internal/repository/redis"
	"github.com/steve-mir/go-auth-system/internal/security/crypto"
	"github.com/steve-mir/go-auth-system/internal/service/email"
)

// PostgresMFARepository implements the MFARepository interface using PostgreSQL
type PostgresMFARepository struct {
	db    *postgres.DB
	store *db.Store
}

// NewPostgresMFARepository creates a new PostgreSQL MFA repository
func NewPostgresMFARepository(db *postgres.DB, store *db.Store) MFARepository {
	return &PostgresMFARepository{
		db:    db,
		store: store,
	}
}

// CreateMFAConfig creates a new MFA configuration
func (r *PostgresMFARepository) CreateMFAConfig(ctx context.Context, config *MFAConfigData) (*MFAConfigData, error) {
	params := db.CreateMFAConfigParams{
		// ID:                   uuid.New(),
		UserID:               uuid.MustParse(config.UserID),
		Method:               config.Method,
		SecretEncrypted:      config.SecretEncrypted,
		BackupCodesEncrypted: config.BackupCodesEncrypted,
		Enabled:              pgtype.Bool{Bool: config.Enabled, Valid: true},
	}

	dbConfig, err := r.store.CreateMFAConfig(ctx, params)
	if err != nil {
		return nil, err
	}

	return &MFAConfigData{
		ID:                   dbConfig.ID.String(),
		UserID:               dbConfig.UserID.String(),
		Method:               dbConfig.Method,
		SecretEncrypted:      dbConfig.SecretEncrypted,
		BackupCodesEncrypted: dbConfig.BackupCodesEncrypted,
		Enabled:              dbConfig.Enabled.Bool,
		CreatedAt:            dbConfig.CreatedAt.Time.Unix(),
		LastUsedAt:           nil, // Set if dbConfig.LastUsedAt is valid
	}, nil
}

// GetMFAConfigByID retrieves MFA config by ID
func (r *PostgresMFARepository) GetMFAConfigByID(ctx context.Context, id string) (*MFAConfigData, error) {
	configID, err := uuid.Parse(id)
	if err != nil {
		return nil, err
	}

	dbConfig, err := r.store.GetMFAConfigByID(ctx, configID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	var lastUsedAt *int64
	if dbConfig.LastUsedAt.Valid {
		timestamp := dbConfig.LastUsedAt.Time.Unix()
		lastUsedAt = &timestamp
	}

	return &MFAConfigData{
		ID:                   dbConfig.ID.String(),
		UserID:               dbConfig.UserID.String(),
		Method:               dbConfig.Method,
		SecretEncrypted:      dbConfig.SecretEncrypted,
		BackupCodesEncrypted: dbConfig.BackupCodesEncrypted,
		Enabled:              dbConfig.Enabled.Bool,
		CreatedAt:            dbConfig.CreatedAt.Time.Unix(),
		LastUsedAt:           lastUsedAt,
	}, nil
}

// GetUserMFAByMethod retrieves user's MFA config for a specific method
func (r *PostgresMFARepository) GetUserMFAByMethod(ctx context.Context, userID, method string) (*MFAConfigData, error) {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, err
	}

	dbConfig, err := r.store.GetUserMFAByMethod(ctx, db.GetUserMFAByMethodParams{
		UserID: userUUID,
		Method: method,
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	var lastUsedAt *int64
	if dbConfig.LastUsedAt.Valid {
		timestamp := dbConfig.LastUsedAt.Time.Unix()
		lastUsedAt = &timestamp
	}

	return &MFAConfigData{
		ID:                   dbConfig.ID.String(),
		UserID:               dbConfig.UserID.String(),
		Method:               dbConfig.Method,
		SecretEncrypted:      dbConfig.SecretEncrypted,
		BackupCodesEncrypted: dbConfig.BackupCodesEncrypted,
		Enabled:              dbConfig.Enabled.Bool,
		CreatedAt:            dbConfig.CreatedAt.Time.Unix(),
		LastUsedAt:           lastUsedAt,
	}, nil
}

// GetUserMFAConfigs retrieves all MFA configs for a user
func (r *PostgresMFARepository) GetUserMFAConfigs(ctx context.Context, userID string) ([]*MFAConfigData, error) {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, err
	}

	dbConfigs, err := r.store.GetUserMFAConfigs(ctx, userUUID)
	if err != nil {
		return nil, err
	}

	configs := make([]*MFAConfigData, len(dbConfigs))
	for i, dbConfig := range dbConfigs {
		var lastUsedAt *int64
		if dbConfig.LastUsedAt.Valid {
			timestamp := dbConfig.LastUsedAt.Time.Unix()
			lastUsedAt = &timestamp
		}

		configs[i] = &MFAConfigData{
			ID:                   dbConfig.ID.String(),
			UserID:               dbConfig.UserID.String(),
			Method:               dbConfig.Method,
			SecretEncrypted:      dbConfig.SecretEncrypted,
			BackupCodesEncrypted: dbConfig.BackupCodesEncrypted,
			Enabled:              dbConfig.Enabled.Bool,
			CreatedAt:            dbConfig.CreatedAt.Time.Unix(),
			LastUsedAt:           lastUsedAt,
		}
	}

	return configs, nil
}

// GetEnabledMFAMethods retrieves enabled MFA methods for a user
func (r *PostgresMFARepository) GetEnabledMFAMethods(ctx context.Context, userID string) ([]string, error) {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, err
	}

	methods, err := r.store.GetEnabledMFAMethods(ctx, userUUID)
	if err != nil {
		return nil, err
	}

	return methods, nil
}

// UpdateMFAConfig updates an MFA configuration
func (r *PostgresMFARepository) UpdateMFAConfig(ctx context.Context, id string, config *UpdateMFAConfigData) (*MFAConfigData, error) {
	configID, err := uuid.Parse(id)
	if err != nil {
		return nil, err
	}

	params := db.UpdateMFAConfigParams{
		ID:                   configID,
		SecretEncrypted:      config.SecretEncrypted,
		BackupCodesEncrypted: config.BackupCodesEncrypted,
	}

	if config.Enabled != nil {
		params.Enabled = pgtype.Bool{Bool: *config.Enabled, Valid: true}
	}

	dbConfig, err := r.store.UpdateMFAConfig(ctx, params)
	if err != nil {
		return nil, err
	}

	var lastUsedAt *int64
	if dbConfig.LastUsedAt.Valid {
		timestamp := dbConfig.LastUsedAt.Time.Unix()
		lastUsedAt = &timestamp
	}

	return &MFAConfigData{
		ID:                   dbConfig.ID.String(),
		UserID:               dbConfig.UserID.String(),
		Method:               dbConfig.Method,
		SecretEncrypted:      dbConfig.SecretEncrypted,
		BackupCodesEncrypted: dbConfig.BackupCodesEncrypted,
		Enabled:              dbConfig.Enabled.Bool,
		CreatedAt:            dbConfig.CreatedAt.Time.Unix(),
		LastUsedAt:           lastUsedAt,
	}, nil
}

// EnableMFA enables an MFA method
func (r *PostgresMFARepository) EnableMFA(ctx context.Context, id string) error {
	configID, err := uuid.Parse(id)
	if err != nil {
		return err
	}

	return r.store.EnableMFA(ctx, configID)
}

// DisableMFA disables an MFA method
func (r *PostgresMFARepository) DisableMFA(ctx context.Context, id string) error {
	configID, err := uuid.Parse(id)
	if err != nil {
		return err
	}

	return r.store.DisableMFA(ctx, configID)
}

// DeleteMFAConfig deletes an MFA configuration
func (r *PostgresMFARepository) DeleteMFAConfig(ctx context.Context, id string) error {
	configID, err := uuid.Parse(id)
	if err != nil {
		return err
	}

	return r.store.DeleteMFAConfig(ctx, configID)
}

// CountUserMFAMethods counts enabled MFA methods for a user
func (r *PostgresMFARepository) CountUserMFAMethods(ctx context.Context, userID string) (int64, error) {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return 0, err
	}

	count, err := r.store.CountUserMFAMethods(ctx, userUUID)
	if err != nil {
		return 0, err
	}

	return count, nil
}

// PostgresUserRepository implements the UserRepository interface for MFA
type PostgresUserRepository struct {
	db        *postgres.DB
	store     *db.Store
	encryptor crypto.Encryptor
}

// NewPostgresUserRepository creates a new PostgreSQL user repository for MFA
func NewPostgresUserRepository(db *postgres.DB, store *db.Store, encryptor crypto.Encryptor) UserRepository {
	return &PostgresUserRepository{
		db:        db,
		store:     store,
		encryptor: encryptor,
	}
}

// GetUserByID retrieves a user by ID
func (r *PostgresUserRepository) GetUserByID(ctx context.Context, userID string) (*UserData, error) {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, err
	}

	dbUser, err := r.store.GetUserByID(ctx, userUUID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &UserData{
		ID:                 dbUser.ID.String(),
		Email:              dbUser.Email,
		Username:           dbUser.Username.String,
		FirstNameEncrypted: dbUser.FirstNameEncrypted,
		LastNameEncrypted:  dbUser.LastNameEncrypted,
		PhoneEncrypted:     dbUser.PhoneEncrypted,
		EmailVerified:      dbUser.EmailVerified.Bool,
		PhoneVerified:      dbUser.PhoneVerified.Bool,
		AccountLocked:      dbUser.AccountLocked.Bool,
	}, nil
}

// RedisCacheService implements the CacheService interface using Redis
type RedisCacheService struct {
	client *redis.Client
}

// NewRedisCacheService creates a new Redis cache service
func NewRedisCacheService(client *redis.Client) CacheService {
	return &RedisCacheService{
		client: client,
	}
}

// Set stores a value with expiration
func (r *RedisCacheService) Set(ctx context.Context, key string, value interface{}, expiration int64) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return r.client.Set(ctx, key, data, time.Duration(expiration)).Err()
}

// Get retrieves a value
func (r *RedisCacheService) Get(ctx context.Context, key string) (interface{}, error) {
	data, err := r.client.Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	var value interface{}
	if err := json.Unmarshal([]byte(data), &value); err != nil {
		return nil, err
	}

	return value, nil
}

// Delete removes a value
func (r *RedisCacheService) Delete(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}

// EmailServiceAdapter adapts the email service to the MFA EmailService interface
type EmailServiceAdapter struct {
	emailService *email.Service
}

// NewEmailServiceAdapter creates a new email service adapter
func NewEmailServiceAdapter(emailService *email.Service) EmailService {
	return &EmailServiceAdapter{
		emailService: emailService,
	}
}

// SendEmail sends an email message
func (a *EmailServiceAdapter) SendEmail(ctx context.Context, to, subject, body string) error {
	return a.emailService.SendEmail(ctx, &interfaces.SendEmailRequest{
		To:       []string{to},
		Subject:  subject,
		HTMLBody: body,
	})
}

// SMSServiceStub is a stub implementation of SMSService
type SMSServiceStub struct{}

// NewSMSServiceStub creates a new SMS service stub
func NewSMSServiceStub() SMSService {
	return &SMSServiceStub{}
}

// SendSMS sends an SMS message (stub implementation)
func (s *SMSServiceStub) SendSMS(ctx context.Context, phoneNumber, message string) error {
	// TODO: Implement actual SMS sending logic
	// For now, just log the message
	return nil
}
