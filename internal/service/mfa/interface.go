package mfa

import (
	"context"

	"github.com/steve-mir/go-auth-system/internal/security/crypto"
)

// MFAService defines the interface for multi-factor authentication operations
type MFAService interface {
	// SetupTOTP sets up TOTP-based MFA for a user
	SetupTOTP(ctx context.Context, req *SetupTOTPRequest) (*SetupTOTPResponse, error)

	// VerifyTOTP verifies a TOTP code for authentication
	VerifyTOTP(ctx context.Context, req *VerifyTOTPRequest) (*VerifyTOTPResponse, error)

	// SetupSMS sets up SMS-based MFA for a user
	SetupSMS(ctx context.Context, req *SetupSMSRequest) (*SetupSMSResponse, error)

	// SendSMSCode sends an SMS verification code
	SendSMSCode(ctx context.Context, req *SendSMSCodeRequest) (*SendSMSCodeResponse, error)

	// VerifySMS verifies an SMS code for authentication
	VerifySMS(ctx context.Context, req *VerifySMSRequest) (*VerifySMSResponse, error)

	// SetupEmail sets up email-based MFA for a user
	SetupEmail(ctx context.Context, req *SetupEmailRequest) (*SetupEmailResponse, error)

	// SendEmailCode sends an email verification code
	SendEmailCode(ctx context.Context, req *SendEmailCodeRequest) (*SendEmailCodeResponse, error)

	// VerifyEmail verifies an email code for authentication
	VerifyEmail(ctx context.Context, req *VerifyEmailRequest) (*VerifyEmailResponse, error)

	// GetUserMFAMethods retrieves all MFA methods for a user
	GetUserMFAMethods(ctx context.Context, userID string) (*GetUserMFAMethodsResponse, error)

	// DisableMFA disables a specific MFA method for a user
	DisableMFA(ctx context.Context, req *DisableMFARequest) error

	// GenerateBackupCodes generates backup codes for MFA recovery
	GenerateBackupCodes(ctx context.Context, req *GenerateBackupCodesRequest) (*GenerateBackupCodesResponse, error)

	// VerifyBackupCode verifies a backup code for MFA recovery
	VerifyBackupCode(ctx context.Context, req *VerifyBackupCodeRequest) (*VerifyBackupCodeResponse, error)

	// ValidateMFAForLogin validates MFA during login process
	ValidateMFAForLogin(ctx context.Context, req *ValidateMFAForLoginRequest) (*ValidateMFAForLoginResponse, error)

	// WebAuthn methods
	// SetupWebAuthn initiates WebAuthn credential registration
	SetupWebAuthn(ctx context.Context, req *SetupWebAuthnRequest) (*SetupWebAuthnResponse, error)

	// FinishWebAuthnSetup completes WebAuthn credential registration
	FinishWebAuthnSetup(ctx context.Context, req *FinishWebAuthnSetupRequest) (*FinishWebAuthnSetupResponse, error)

	// BeginWebAuthnLogin initiates WebAuthn authentication
	BeginWebAuthnLogin(ctx context.Context, req *BeginWebAuthnLoginRequest) (*BeginWebAuthnLoginResponse, error)

	// FinishWebAuthnLogin completes WebAuthn authentication
	FinishWebAuthnLogin(ctx context.Context, req *FinishWebAuthnLoginRequest) (*FinishWebAuthnLoginResponse, error)
}

// Repository interfaces that the MFA service depends on
type MFARepository interface {
	// CreateMFAConfig creates a new MFA configuration
	CreateMFAConfig(ctx context.Context, config *MFAConfigData) (*MFAConfigData, error)

	// GetMFAConfigByID retrieves MFA config by ID
	GetMFAConfigByID(ctx context.Context, id string) (*MFAConfigData, error)

	// GetUserMFAByMethod retrieves user's MFA config for a specific method
	GetUserMFAByMethod(ctx context.Context, userID, method string) (*MFAConfigData, error)

	// GetUserMFAConfigs retrieves all MFA configs for a user
	GetUserMFAConfigs(ctx context.Context, userID string) ([]*MFAConfigData, error)

	// GetEnabledMFAMethods retrieves enabled MFA methods for a user
	GetEnabledMFAMethods(ctx context.Context, userID string) ([]string, error)

	// UpdateMFAConfig updates an MFA configuration
	UpdateMFAConfig(ctx context.Context, id string, config *UpdateMFAConfigData) (*MFAConfigData, error)

	// EnableMFA enables an MFA method
	EnableMFA(ctx context.Context, id string) error

	// DisableMFA disables an MFA method
	DisableMFA(ctx context.Context, id string) error

	// DeleteMFAConfig deletes an MFA configuration
	DeleteMFAConfig(ctx context.Context, id string) error

	// CountUserMFAMethods counts enabled MFA methods for a user
	CountUserMFAMethods(ctx context.Context, userID string) (int64, error)
}

// UserRepository interface for user-related operations
type UserRepository interface {
	// GetUserByID retrieves a user by ID
	GetUserByID(ctx context.Context, userID string) (*UserData, error)
}

// SMSService interface for SMS operations
type SMSService interface {
	// SendSMS sends an SMS message
	SendSMS(ctx context.Context, phoneNumber, message string) error
}

// EmailService interface for email operations
type EmailService interface {
	// SendEmail sends an email message
	SendEmail(ctx context.Context, to, subject, body string) error
}

// CacheService interface for caching verification codes
type CacheService interface {
	// Set stores a value with expiration
	Set(ctx context.Context, key string, value interface{}, expiration int64) error

	// Get retrieves a value
	Get(ctx context.Context, key string) (interface{}, error)

	// Delete removes a value
	Delete(ctx context.Context, key string) error
}

// Data transfer objects
type MFAConfigData struct {
	ID                   string
	UserID               string
	Method               string
	SecretEncrypted      []byte
	BackupCodesEncrypted []byte
	Enabled              bool
	CreatedAt            int64
	LastUsedAt           *int64
}

type UpdateMFAConfigData struct {
	SecretEncrypted      []byte
	BackupCodesEncrypted []byte
	Enabled              *bool
	UpdateLastUsed       bool
}

type UserData struct {
	ID                 string
	Email              string
	Username           string
	FirstNameEncrypted []byte
	LastNameEncrypted  []byte
	PhoneEncrypted     []byte
	EmailVerified      bool
	PhoneVerified      bool
	AccountLocked      bool
}

// Dependencies interface for external services
type Dependencies struct {
	MFARepo      MFARepository
	UserRepo     UserRepository
	SMSService   SMSService
	EmailService EmailService
	CacheService CacheService
	Encryptor    Encryptor
}

// Use the crypto package encryptor
type Encryptor = crypto.Encryptor
