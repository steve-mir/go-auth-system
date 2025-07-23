package mfa

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/steve-mir/go-auth-system/internal/config"
	"github.com/steve-mir/go-auth-system/internal/errors"
)

// mfaService implements the MFAService interface
type mfaService struct {
	config       *config.Config
	mfaRepo      MFARepository
	userRepo     UserRepository
	smsService   SMSService
	emailService EmailService
	cacheService CacheService
	encryptor    Encryptor
	webAuthn     *webauthn.WebAuthn
}

// NewMFAService creates a new MFA service
func NewMFAService(cfg *config.Config, deps *Dependencies) MFAService {
	// Initialize WebAuthn
	webAuthnConfig := &webauthn.Config{
		RPDisplayName: cfg.Features.MFA.WebAuthn.RPDisplayName,
		RPID:          cfg.Features.MFA.WebAuthn.RPID,
		// RPName:        cfg.Features.MFA.WebAuthn.RPName,
		RPOrigins: cfg.Features.MFA.WebAuthn.RPOrigin,
	}

	// Set defaults if not configured
	if webAuthnConfig.RPDisplayName == "" {
		webAuthnConfig.RPDisplayName = "Go Auth System"
	}
	if webAuthnConfig.RPID == "" {
		webAuthnConfig.RPID = "localhost"
	}
	// if webAuthnConfig.RPName == "" {
	// 	webAuthnConfig.RPName = "Go Auth System"
	// }
	if len(webAuthnConfig.RPOrigins) == 0 {
		webAuthnConfig.RPOrigins = []string{"http://localhost:8080"}
	}

	webAuthnInstance, err := webauthn.New(webAuthnConfig)
	if err != nil {
		// Log error but don't fail service creation
		// In production, you might want to handle this differently
		webAuthnInstance = nil
	}

	return &mfaService{
		config:       cfg,
		mfaRepo:      deps.MFARepo,
		userRepo:     deps.UserRepo,
		smsService:   deps.SMSService,
		emailService: deps.EmailService,
		cacheService: deps.CacheService,
		encryptor:    deps.Encryptor,
		webAuthn:     webAuthnInstance,
	}
}

// SetupTOTP sets up TOTP-based MFA for a user
func (s *mfaService) SetupTOTP(ctx context.Context, req *SetupTOTPRequest) (*SetupTOTPResponse, error) {
	// Validate request
	if err := s.validateSetupTOTPRequest(req); err != nil {
		return nil, err
	}

	// Check if user exists
	user, err := s.userRepo.GetUserByID(ctx, req.UserID)
	if err != nil || user == nil {
		return nil, ErrUserNotFound
	}

	if user.AccountLocked {
		return nil, ErrUserAccountLocked
	}

	// Check if TOTP is already configured for this user
	existingConfig, _ := s.mfaRepo.GetUserMFAByMethod(ctx, req.UserID, MethodTOTP)
	if existingConfig != nil && existingConfig.Enabled {
		return nil, ErrMFAAlreadyExists.WithDetails("TOTP is already configured for this user")
	}

	// Generate TOTP secret
	secret, err := s.generateTOTPSecret()
	if err != nil {
		return nil, ErrTOTPSecretGeneration.WithCause(err)
	}

	// Encrypt the secret
	encryptedSecret, err := s.encryptor.Encrypt([]byte(secret))
	if err != nil {
		return nil, ErrEncryptionFailed.WithCause(err)
	}

	// Generate backup codes
	backupCodes, err := s.generateBackupCodes()
	if err != nil {
		return nil, ErrBackupCodeGenerationFailed.WithCause(err)
	}

	// Encrypt backup codes
	backupCodesJSON, _ := json.Marshal(backupCodes)
	encryptedBackupCodes, err := s.encryptor.Encrypt(backupCodesJSON)
	if err != nil {
		return nil, ErrEncryptionFailed.WithCause(err)
	}

	// Create MFA config (initially disabled until verified)
	configData := &MFAConfigData{
		UserID:               req.UserID,
		Method:               MethodTOTP,
		SecretEncrypted:      encryptedSecret,
		BackupCodesEncrypted: encryptedBackupCodes,
		Enabled:              false, // Will be enabled after verification
	}

	// Save to database
	createdConfig, err := s.mfaRepo.CreateMFAConfig(ctx, configData)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "MFA_CONFIG_CREATION_FAILED", "Failed to create MFA configuration")
	}

	// Generate QR code URL
	accountName := req.AccountName
	if accountName == "" {
		accountName = user.Email
	}

	issuer := req.Issuer
	if issuer == "" {
		issuer = s.config.Features.MFA.TOTP.Issuer
		if issuer == "" {
			issuer = "Go Auth System"
		}
	}

	qrCodeURL, err := s.generateTOTPQRCode(secret, accountName, issuer)
	if err != nil {
		return nil, ErrTOTPQRCodeGeneration.WithCause(err)
	}

	// Create setup token for verification
	setupToken, err := s.createTOTPSetupToken(req.UserID, createdConfig.ID, secret)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "SETUP_TOKEN_CREATION_FAILED", "Failed to create setup token")
	}

	return &SetupTOTPResponse{
		ConfigID:    uuid.MustParse(createdConfig.ID),
		Secret:      secret,
		QRCodeURL:   qrCodeURL,
		BackupCodes: backupCodes,
		SetupToken:  setupToken,
		Message:     "TOTP setup initiated. Please verify with your authenticator app to complete setup.",
	}, nil
}

// VerifyTOTP verifies a TOTP code for authentication
func (s *mfaService) VerifyTOTP(ctx context.Context, req *VerifyTOTPRequest) (*VerifyTOTPResponse, error) {
	// Validate request
	if err := s.validateVerifyTOTPRequest(req); err != nil {
		return nil, err
	}

	var config *MFAConfigData
	var secret string
	var setupComplete bool

	// Handle setup verification vs regular verification
	if req.SetupToken != "" {
		// This is setup verification
		setupData, err := s.validateTOTPSetupToken(req.SetupToken)
		if err != nil {
			return nil, err
		}

		// Get the config
		config, err = s.mfaRepo.GetMFAConfigByID(ctx, setupData.ConfigID)
		if err != nil || config == nil {
			return nil, ErrMFANotFound
		}

		secret = setupData.Secret
		setupComplete = true
	} else {
		// This is regular verification
		var err error
		if req.ConfigID != "" {
			config, err = s.mfaRepo.GetMFAConfigByID(ctx, req.ConfigID)
		} else if req.UserID != "" {
			config, err = s.mfaRepo.GetUserMFAByMethod(ctx, req.UserID, MethodTOTP)
		} else {
			return nil, errors.New(errors.ErrorTypeValidation, "MISSING_IDENTIFIER", "Either user_id or config_id must be provided")
		}

		if err != nil || config == nil {
			return nil, ErrMFANotFound
		}

		if !config.Enabled && !setupComplete {
			return nil, ErrMFANotEnabled
		}

		// Decrypt secret
		decryptedSecret, err := s.encryptor.Decrypt(config.SecretEncrypted)
		if err != nil {
			return nil, ErrDecryptionFailed.WithCause(err)
		}
		secret = string(decryptedSecret)
	}

	// Verify TOTP code
	valid := totp.Validate(req.Code, secret)
	if !valid {
		// Try with time window for clock skew
		// now := time.Now()
		for i := -TOTPWindowSize; i <= TOTPWindowSize; i++ {
			// testTime := now.Add(time.Duration(i) * 30 * time.Second)
			if totp.Validate(req.Code, secret) {
				valid = true
				break
			}
		}
	}

	if !valid {
		return nil, ErrInvalidTOTPCode
	}

	// If this was setup verification, enable the MFA method
	if setupComplete {
		err := s.mfaRepo.EnableMFA(ctx, config.ID)
		if err != nil {
			return nil, errors.Wrap(err, errors.ErrorTypeInternal, "MFA_ENABLE_FAILED", "Failed to enable MFA method")
		}

		// Clean up setup token
		s.cacheService.Delete(ctx, CacheKeyTOTPSetup+req.SetupToken)
	} else {
		// Update last used timestamp for regular verification
		updateData := &UpdateMFAConfigData{
			UpdateLastUsed: true,
		}
		s.mfaRepo.UpdateMFAConfig(ctx, config.ID, updateData)
	}

	return &VerifyTOTPResponse{
		Valid:         true,
		ConfigID:      config.ID,
		Message:       "TOTP code verified successfully",
		SetupComplete: setupComplete,
	}, nil
}

// SetupSMS sets up SMS-based MFA for a user
func (s *mfaService) SetupSMS(ctx context.Context, req *SetupSMSRequest) (*SetupSMSResponse, error) {
	// Validate request
	if err := s.validateSetupSMSRequest(req); err != nil {
		return nil, err
	}

	// Check if user exists
	user, err := s.userRepo.GetUserByID(ctx, req.UserID)
	if err != nil || user == nil {
		return nil, ErrUserNotFound
	}

	if user.AccountLocked {
		return nil, ErrUserAccountLocked
	}

	// Validate phone number format
	if !s.isValidPhoneNumber(req.PhoneNumber) {
		return nil, ErrInvalidPhoneNumber
	}

	// Check if SMS MFA is already configured for this user
	existingConfig, _ := s.mfaRepo.GetUserMFAByMethod(ctx, req.UserID, MethodSMS)
	if existingConfig != nil && existingConfig.Enabled {
		return nil, ErrMFAAlreadyExists.WithDetails("SMS MFA is already configured for this user")
	}

	// Encrypt phone number
	encryptedPhone, err := s.encryptor.Encrypt([]byte(req.PhoneNumber))
	if err != nil {
		return nil, ErrEncryptionFailed.WithCause(err)
	}

	// Generate backup codes
	backupCodes, err := s.generateBackupCodes()
	if err != nil {
		return nil, ErrBackupCodeGenerationFailed.WithCause(err)
	}

	// Encrypt backup codes
	backupCodesJSON, _ := json.Marshal(backupCodes)
	encryptedBackupCodes, err := s.encryptor.Encrypt(backupCodesJSON)
	if err != nil {
		return nil, ErrEncryptionFailed.WithCause(err)
	}

	// Create MFA config (enabled immediately for SMS)
	configData := &MFAConfigData{
		UserID:               req.UserID,
		Method:               MethodSMS,
		SecretEncrypted:      encryptedPhone,
		BackupCodesEncrypted: encryptedBackupCodes,
		Enabled:              true,
	}

	// Save to database
	createdConfig, err := s.mfaRepo.CreateMFAConfig(ctx, configData)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "MFA_CONFIG_CREATION_FAILED", "Failed to create MFA configuration")
	}

	return &SetupSMSResponse{
		ConfigID:    uuid.MustParse(createdConfig.ID),
		PhoneNumber: s.maskPhoneNumber(req.PhoneNumber),
		BackupCodes: backupCodes,
		Message:     "SMS MFA setup completed successfully",
	}, nil
}

// SendSMSCode sends an SMS verification code
func (s *mfaService) SendSMSCode(ctx context.Context, req *SendSMSCodeRequest) (*SendSMSCodeResponse, error) {
	// Validate request
	if err := s.validateSendSMSCodeRequest(req); err != nil {
		return nil, err
	}

	// Get MFA config
	var config *MFAConfigData
	var err error

	if req.ConfigID != "" {
		config, err = s.mfaRepo.GetMFAConfigByID(ctx, req.ConfigID)
	} else {
		config, err = s.mfaRepo.GetUserMFAByMethod(ctx, req.UserID, MethodSMS)
	}

	if err != nil || config == nil {
		return nil, ErrMFANotFound
	}

	if !config.Enabled {
		return nil, ErrMFANotEnabled
	}

	// Decrypt phone number
	decryptedPhone, err := s.encryptor.Decrypt(config.SecretEncrypted)
	if err != nil {
		return nil, ErrDecryptionFailed.WithCause(err)
	}
	phoneNumber := string(decryptedPhone)

	// Generate verification code
	code, err := s.generateVerificationCode(SMSCodeLength)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "CODE_GENERATION_FAILED", "Failed to generate verification code")
	}

	// Store code in cache
	codeData := &VerificationCode{
		Code:      code,
		UserID:    config.UserID,
		ConfigID:  config.ID,
		Method:    MethodSMS,
		ExpiresAt: time.Now().Add(time.Duration(SMSCodeExpiration) * time.Second),
		ForLogin:  req.ForLogin,
	}

	cacheKey := fmt.Sprintf("%s%s:%s", CacheKeySMSCode, config.UserID, config.ID)
	if err := s.cacheService.Set(ctx, cacheKey, codeData, SMSCodeExpiration); err != nil {
		return nil, ErrCacheOperationFailed.WithCause(err)
	}

	// Send SMS
	message := fmt.Sprintf("Your verification code is: %s. This code will expire in %d minutes.", code, SMSCodeExpiration/60)
	if err := s.smsService.SendSMS(ctx, phoneNumber, message); err != nil {
		return nil, ErrSMSSendFailed.WithCause(err)
	}

	return &SendSMSCodeResponse{
		CodeSent:    true,
		ExpiresIn:   SMSCodeExpiration,
		Message:     "SMS verification code sent successfully",
		PhoneNumber: s.maskPhoneNumber(phoneNumber),
	}, nil
}

// VerifySMS verifies an SMS code for authentication
func (s *mfaService) VerifySMS(ctx context.Context, req *VerifySMSRequest) (*VerifySMSResponse, error) {
	// Validate request
	if err := s.validateVerifySMSRequest(req); err != nil {
		return nil, err
	}

	// Get MFA config
	var config *MFAConfigData
	var err error

	if req.ConfigID != "" {
		config, err = s.mfaRepo.GetMFAConfigByID(ctx, req.ConfigID)
	} else if req.UserID != "" {
		config, err = s.mfaRepo.GetUserMFAByMethod(ctx, req.UserID, MethodSMS)
	} else {
		return nil, errors.New(errors.ErrorTypeValidation, "MISSING_IDENTIFIER", "Either user_id or config_id must be provided")
	}

	if err != nil || config == nil {
		return nil, ErrMFANotFound
	}

	if !config.Enabled {
		return nil, ErrMFANotEnabled
	}

	// Get stored code from cache
	cacheKey := fmt.Sprintf("%s%s:%s", CacheKeySMSCode, config.UserID, config.ID)
	cachedData, err := s.cacheService.Get(ctx, cacheKey)
	if err != nil {
		return nil, ErrSMSCodeNotFound
	}

	var codeData VerificationCode
	if err := json.Unmarshal(cachedData.([]byte), &codeData); err != nil {
		return nil, ErrSMSCodeNotFound
	}

	// Check if code has expired
	if time.Now().After(codeData.ExpiresAt) {
		s.cacheService.Delete(ctx, cacheKey)
		return nil, ErrSMSCodeExpired
	}

	// Verify code using constant-time comparison
	if subtle.ConstantTimeCompare([]byte(req.Code), []byte(codeData.Code)) != 1 {
		return nil, ErrInvalidSMSCode
	}

	// Delete used code
	s.cacheService.Delete(ctx, cacheKey)

	// Update last used timestamp
	updateData := &UpdateMFAConfigData{
		UpdateLastUsed: true,
	}
	s.mfaRepo.UpdateMFAConfig(ctx, config.ID, updateData)

	return &VerifySMSResponse{
		Valid:    true,
		ConfigID: config.ID,
		Message:  "SMS code verified successfully",
	}, nil
}

// SetupEmail sets up email-based MFA for a user
func (s *mfaService) SetupEmail(ctx context.Context, req *SetupEmailRequest) (*SetupEmailResponse, error) {
	// Validate request
	if err := s.validateSetupEmailRequest(req); err != nil {
		return nil, err
	}

	// Check if user exists
	user, err := s.userRepo.GetUserByID(ctx, req.UserID)
	if err != nil || user == nil {
		return nil, ErrUserNotFound
	}

	if user.AccountLocked {
		return nil, ErrUserAccountLocked
	}

	// Validate email format
	if !s.isValidEmail(req.Email) {
		return nil, ErrInvalidEmailAddress
	}

	// Check if email MFA is already configured for this user
	existingConfig, _ := s.mfaRepo.GetUserMFAByMethod(ctx, req.UserID, MethodEmail)
	if existingConfig != nil && existingConfig.Enabled {
		return nil, ErrMFAAlreadyExists.WithDetails("Email MFA is already configured for this user")
	}

	// Encrypt email
	encryptedEmail, err := s.encryptor.Encrypt([]byte(req.Email))
	if err != nil {
		return nil, ErrEncryptionFailed.WithCause(err)
	}

	// Generate backup codes
	backupCodes, err := s.generateBackupCodes()
	if err != nil {
		return nil, ErrBackupCodeGenerationFailed.WithCause(err)
	}

	// Encrypt backup codes
	backupCodesJSON, _ := json.Marshal(backupCodes)
	encryptedBackupCodes, err := s.encryptor.Encrypt(backupCodesJSON)
	if err != nil {
		return nil, ErrEncryptionFailed.WithCause(err)
	}

	// Create MFA config (enabled immediately for email)
	configData := &MFAConfigData{
		UserID:               req.UserID,
		Method:               MethodEmail,
		SecretEncrypted:      encryptedEmail,
		BackupCodesEncrypted: encryptedBackupCodes,
		Enabled:              true,
	}

	// Save to database
	createdConfig, err := s.mfaRepo.CreateMFAConfig(ctx, configData)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "MFA_CONFIG_CREATION_FAILED", "Failed to create MFA configuration")
	}

	return &SetupEmailResponse{
		ConfigID:    uuid.MustParse(createdConfig.ID),
		Email:       s.maskEmail(req.Email),
		BackupCodes: backupCodes,
		Message:     "Email MFA setup completed successfully",
	}, nil
}

// SendEmailCode sends an email verification code
func (s *mfaService) SendEmailCode(ctx context.Context, req *SendEmailCodeRequest) (*SendEmailCodeResponse, error) {
	// Validate request
	if err := s.validateSendEmailCodeRequest(req); err != nil {
		return nil, err
	}

	// Get MFA config
	var config *MFAConfigData
	var err error

	if req.ConfigID != "" {
		config, err = s.mfaRepo.GetMFAConfigByID(ctx, req.ConfigID)
	} else {
		config, err = s.mfaRepo.GetUserMFAByMethod(ctx, req.UserID, MethodEmail)
	}

	if err != nil || config == nil {
		return nil, ErrMFANotFound
	}

	if !config.Enabled {
		return nil, ErrMFANotEnabled
	}

	// Decrypt email
	decryptedEmail, err := s.encryptor.Decrypt(config.SecretEncrypted)
	if err != nil {
		return nil, ErrDecryptionFailed.WithCause(err)
	}
	email := string(decryptedEmail)

	// Generate verification code
	code, err := s.generateVerificationCode(EmailCodeLength)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "CODE_GENERATION_FAILED", "Failed to generate verification code")
	}

	// Store code in cache
	codeData := &VerificationCode{
		Code:      code,
		UserID:    config.UserID,
		ConfigID:  config.ID,
		Method:    MethodEmail,
		ExpiresAt: time.Now().Add(time.Duration(EmailCodeExpiration) * time.Second),
		ForLogin:  req.ForLogin,
	}

	cacheKey := fmt.Sprintf("%s%s:%s", CacheKeyEmailCode, config.UserID, config.ID)
	if err := s.cacheService.Set(ctx, cacheKey, codeData, EmailCodeExpiration); err != nil {
		return nil, ErrCacheOperationFailed.WithCause(err)
	}

	// Send email
	subject := s.config.Features.MFA.Email.Subject
	if subject == "" {
		subject = "Your verification code"
	}

	body := fmt.Sprintf("Your verification code is: %s\n\nThis code will expire in %d minutes.\n\nIf you did not request this code, please ignore this email.",
		code, EmailCodeExpiration/60)

	if err := s.emailService.SendEmail(ctx, email, subject, body); err != nil {
		return nil, ErrEmailSendFailed.WithCause(err)
	}

	return &SendEmailCodeResponse{
		CodeSent:  true,
		ExpiresIn: EmailCodeExpiration,
		Message:   "Email verification code sent successfully",
		Email:     s.maskEmail(email),
	}, nil
}

// VerifyEmail verifies an email code for authentication
func (s *mfaService) VerifyEmail(ctx context.Context, req *VerifyEmailRequest) (*VerifyEmailResponse, error) {
	// Validate request
	if err := s.validateVerifyEmailRequest(req); err != nil {
		return nil, err
	}

	// Get MFA config
	var config *MFAConfigData
	var err error

	if req.ConfigID != "" {
		config, err = s.mfaRepo.GetMFAConfigByID(ctx, req.ConfigID)
	} else if req.UserID != "" {
		config, err = s.mfaRepo.GetUserMFAByMethod(ctx, req.UserID, MethodEmail)
	} else {
		return nil, errors.New(errors.ErrorTypeValidation, "MISSING_IDENTIFIER", "Either user_id or config_id must be provided")
	}

	if err != nil || config == nil {
		return nil, ErrMFANotFound
	}

	if !config.Enabled {
		return nil, ErrMFANotEnabled
	}

	// Get stored code from cache
	cacheKey := fmt.Sprintf("%s%s:%s", CacheKeyEmailCode, config.UserID, config.ID)
	cachedData, err := s.cacheService.Get(ctx, cacheKey)
	if err != nil {
		return nil, ErrEmailCodeNotFound
	}

	var codeData VerificationCode
	if err := json.Unmarshal(cachedData.([]byte), &codeData); err != nil {
		return nil, ErrEmailCodeNotFound
	}

	// Check if code has expired
	if time.Now().After(codeData.ExpiresAt) {
		s.cacheService.Delete(ctx, cacheKey)
		return nil, ErrEmailCodeExpired
	}

	// Verify code using constant-time comparison
	if subtle.ConstantTimeCompare([]byte(req.Code), []byte(codeData.Code)) != 1 {
		return nil, ErrInvalidEmailCode
	}

	// Delete used code
	s.cacheService.Delete(ctx, cacheKey)

	// Update last used timestamp
	updateData := &UpdateMFAConfigData{
		UpdateLastUsed: true,
	}
	s.mfaRepo.UpdateMFAConfig(ctx, config.ID, updateData)

	return &VerifyEmailResponse{
		Valid:    true,
		ConfigID: config.ID,
		Message:  "Email code verified successfully",
	}, nil
}

// GetUserMFAMethods retrieves all MFA methods for a user
func (s *mfaService) GetUserMFAMethods(ctx context.Context, userID string) (*GetUserMFAMethodsResponse, error) {
	// Validate user ID
	if _, err := uuid.Parse(userID); err != nil {
		return nil, errors.New(errors.ErrorTypeValidation, "INVALID_USER_ID", "Invalid user ID format")
	}

	// Check if user exists
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return nil, ErrUserNotFound
	}

	// Get all MFA configs for the user
	configs, err := s.mfaRepo.GetUserMFAConfigs(ctx, userID)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "MFA_CONFIGS_RETRIEVAL_FAILED", "Failed to retrieve MFA configurations")
	}

	// Convert to response format
	methods := make([]MFAMethodInfo, 0, len(configs))
	for _, config := range configs {
		displayName := s.getDisplayName(config)

		var lastUsedAt *time.Time
		if config.LastUsedAt != nil {
			t := time.Unix(*config.LastUsedAt, 0)
			lastUsedAt = &t
		}

		methods = append(methods, MFAMethodInfo{
			ID:          uuid.MustParse(config.ID),
			Method:      config.Method,
			Enabled:     config.Enabled,
			CreatedAt:   time.Unix(config.CreatedAt, 0),
			LastUsedAt:  lastUsedAt,
			DisplayName: displayName,
		})
	}

	return &GetUserMFAMethodsResponse{
		Methods: methods,
	}, nil
}

// DisableMFA disables a specific MFA method for a user
func (s *mfaService) DisableMFA(ctx context.Context, req *DisableMFARequest) error {
	// Validate request
	if err := s.validateDisableMFARequest(req); err != nil {
		return err
	}

	// Get MFA config
	config, err := s.mfaRepo.GetMFAConfigByID(ctx, req.ConfigID)
	if err != nil || config == nil {
		return ErrMFANotFound
	}

	// Verify the config belongs to the user
	if config.UserID != req.UserID {
		return errors.New(errors.ErrorTypeAuthorization, "MFA_CONFIG_ACCESS_DENIED", "Access denied to MFA configuration")
	}

	// Verify the method matches
	if config.Method != req.Method {
		return errors.New(errors.ErrorTypeValidation, "MFA_METHOD_MISMATCH", "MFA method does not match configuration")
	}

	// Disable the MFA method
	if err := s.mfaRepo.DisableMFA(ctx, req.ConfigID); err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, "MFA_DISABLE_FAILED", "Failed to disable MFA method")
	}

	return nil
}

// GenerateBackupCodes generates backup codes for MFA recovery
func (s *mfaService) GenerateBackupCodes(ctx context.Context, req *GenerateBackupCodesRequest) (*GenerateBackupCodesResponse, error) {
	// Validate request
	if err := s.validateGenerateBackupCodesRequest(req); err != nil {
		return nil, err
	}

	// Get MFA config
	config, err := s.mfaRepo.GetMFAConfigByID(ctx, req.ConfigID)
	if err != nil || config == nil {
		return nil, ErrMFANotFound
	}

	// Verify the config belongs to the user
	if config.UserID != req.UserID {
		return nil, errors.New(errors.ErrorTypeAuthorization, "MFA_CONFIG_ACCESS_DENIED", "Access denied to MFA configuration")
	}

	if !config.Enabled {
		return nil, ErrMFANotEnabled
	}

	// Generate new backup codes
	backupCodes, err := s.generateBackupCodes()
	if err != nil {
		return nil, ErrBackupCodeGenerationFailed.WithCause(err)
	}

	// Encrypt backup codes
	backupCodesJSON, _ := json.Marshal(backupCodes)
	encryptedBackupCodes, err := s.encryptor.Encrypt(backupCodesJSON)
	if err != nil {
		return nil, ErrEncryptionFailed.WithCause(err)
	}

	// Update MFA config with new backup codes
	updateData := &UpdateMFAConfigData{
		BackupCodesEncrypted: encryptedBackupCodes,
	}

	_, err = s.mfaRepo.UpdateMFAConfig(ctx, req.ConfigID, updateData)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "BACKUP_CODES_UPDATE_FAILED", "Failed to update backup codes")
	}

	return &GenerateBackupCodesResponse{
		BackupCodes: backupCodes,
		Message:     "New backup codes generated successfully",
	}, nil
}

// VerifyBackupCode verifies a backup code for MFA recovery
func (s *mfaService) VerifyBackupCode(ctx context.Context, req *VerifyBackupCodeRequest) (*VerifyBackupCodeResponse, error) {
	// Validate request
	if err := s.validateVerifyBackupCodeRequest(req); err != nil {
		return nil, err
	}

	// Get all enabled MFA configs for the user
	configs, err := s.mfaRepo.GetUserMFAConfigs(ctx, req.UserID)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "MFA_CONFIGS_RETRIEVAL_FAILED", "Failed to retrieve MFA configurations")
	}

	// Check backup codes across all enabled MFA methods
	for _, config := range configs {
		if !config.Enabled || config.BackupCodesEncrypted == nil {
			continue
		}

		// Decrypt backup codes
		decryptedCodes, err := s.encryptor.Decrypt(config.BackupCodesEncrypted)
		if err != nil {
			continue // Skip this config if decryption fails
		}

		var backupCodes []string
		if err := json.Unmarshal(decryptedCodes, &backupCodes); err != nil {
			continue // Skip this config if unmarshaling fails
		}

		// Check if the provided code matches any backup code
		for i, code := range backupCodes {
			if subtle.ConstantTimeCompare([]byte(req.BackupCode), []byte(code)) == 1 {
				// Code matches, remove it from the list (single use)
				backupCodes = append(backupCodes[:i], backupCodes[i+1:]...)

				// Re-encrypt and update the backup codes
				updatedCodesJSON, _ := json.Marshal(backupCodes)
				encryptedUpdatedCodes, err := s.encryptor.Encrypt(updatedCodesJSON)
				if err != nil {
					return nil, ErrEncryptionFailed.WithCause(err)
				}

				updateData := &UpdateMFAConfigData{
					BackupCodesEncrypted: encryptedUpdatedCodes,
					UpdateLastUsed:       true,
				}

				s.mfaRepo.UpdateMFAConfig(ctx, config.ID, updateData)

				return &VerifyBackupCodeResponse{
					Valid:   true,
					Message: "Backup code verified successfully",
				}, nil
			}
		}
	}

	return &VerifyBackupCodeResponse{
		Valid:   false,
		Message: "Invalid backup code",
	}, nil
}

// ValidateMFAForLogin validates MFA during login process
func (s *mfaService) ValidateMFAForLogin(ctx context.Context, req *ValidateMFAForLoginRequest) (*ValidateMFAForLoginResponse, error) {
	// Validate request
	if _, err := uuid.Parse(req.UserID); err != nil {
		return nil, errors.New(errors.ErrorTypeValidation, "INVALID_USER_ID", "Invalid user ID format")
	}

	// Check if user exists
	user, err := s.userRepo.GetUserByID(ctx, req.UserID)
	if err != nil || user == nil {
		return nil, ErrUserNotFound
	}

	if user.AccountLocked {
		return nil, ErrUserAccountLocked
	}

	// Get enabled MFA methods for the user
	enabledMethods, err := s.mfaRepo.GetEnabledMFAMethods(ctx, req.UserID)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "MFA_METHODS_RETRIEVAL_FAILED", "Failed to retrieve MFA methods")
	}

	// If no MFA methods are enabled, MFA is not required
	if len(enabledMethods) == 0 {
		return &ValidateMFAForLoginResponse{
			MFARequired: false,
		}, nil
	}

	// Get MFA configs for display information
	configs, err := s.mfaRepo.GetUserMFAConfigs(ctx, req.UserID)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "MFA_CONFIGS_RETRIEVAL_FAILED", "Failed to retrieve MFA configurations")
	}

	// Build config info for enabled methods
	var configInfos []MFAConfigInfo
	for _, config := range configs {
		if config.Enabled {
			configInfos = append(configInfos, MFAConfigInfo{
				ID:          config.ID,
				Method:      config.Method,
				DisplayName: s.getDisplayName(config),
			})
		}
	}

	// Generate challenge token for MFA flow
	challenge := uuid.New().String()

	return &ValidateMFAForLoginResponse{
		MFARequired: true,
		Methods:     enabledMethods,
		Configs:     configInfos,
		Challenge:   challenge,
	}, nil
}

// Helper methods for TOTP

func (s *mfaService) generateTOTPSecret() (string, error) {
	secret := make([]byte, 20) // 160 bits
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

func (s *mfaService) generateTOTPQRCode(secret, accountName, issuer string) (string, error) {
	key, err := otp.NewKeyFromURL(fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
		url.QueryEscape(issuer),
		url.QueryEscape(accountName),
		secret,
		url.QueryEscape(issuer)))
	if err != nil {
		return "", err
	}
	return key.URL(), nil
}

func (s *mfaService) createTOTPSetupToken(userID, configID, secret string) (string, error) {
	tokenID := uuid.New().String()
	setupData := &TOTPSetupToken{
		UserID:    userID,
		ConfigID:  configID,
		Secret:    secret,
		ExpiresAt: time.Now().Add(time.Duration(TOTPSetupTokenExpiration) * time.Second),
	}

	cacheKey := CacheKeyTOTPSetup + tokenID
	if err := s.cacheService.Set(context.Background(), cacheKey, setupData, TOTPSetupTokenExpiration); err != nil {
		return "", err
	}

	return tokenID, nil
}

func (s *mfaService) validateTOTPSetupToken(token string) (*TOTPSetupToken, error) {
	cacheKey := CacheKeyTOTPSetup + token
	cachedData, err := s.cacheService.Get(context.Background(), cacheKey)
	if err != nil {
		return nil, ErrInvalidTOTPSetupToken
	}

	var setupData TOTPSetupToken
	if err := json.Unmarshal(cachedData.([]byte), &setupData); err != nil {
		return nil, ErrInvalidTOTPSetupToken
	}

	if time.Now().After(setupData.ExpiresAt) {
		s.cacheService.Delete(context.Background(), cacheKey)
		return nil, ErrInvalidTOTPSetupToken
	}

	return &setupData, nil
}

// Helper methods for backup codes

func (s *mfaService) generateBackupCodes() ([]string, error) {
	codes := make([]string, BackupCodesCount)
	for i := 0; i < BackupCodesCount; i++ {
		code, err := s.generateVerificationCode(BackupCodeLength)
		if err != nil {
			return nil, err
		}
		codes[i] = code
	}
	return codes, nil
}

func (s *mfaService) generateVerificationCode(length int) (string, error) {
	const charset = "0123456789"
	code := make([]byte, length)
	for i := range code {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		code[i] = charset[num.Int64()]
	}
	return string(code), nil
}

// Helper methods for phone number handling

func (s *mfaService) isValidPhoneNumber(phone string) bool {
	// Basic E.164 format validation
	phoneRegex := regexp.MustCompile(`^\+[1-9]\d{1,14}$`)
	return phoneRegex.MatchString(phone)
}

func (s *mfaService) maskPhoneNumber(phone string) string {
	if len(phone) < 4 {
		return phone
	}
	return phone[:3] + strings.Repeat("*", len(phone)-6) + phone[len(phone)-3:]
}

// Helper methods for email handling

func (s *mfaService) isValidEmail(email string) bool {
	// Basic email validation
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

func (s *mfaService) maskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email
	}

	username := parts[0]
	domain := parts[1]

	if len(username) <= 2 {
		return email
	}

	maskedUsername := username[:1] + strings.Repeat("*", len(username)-2) + username[len(username)-1:]
	return maskedUsername + "@" + domain
}

// Helper method to get display name for MFA method
func (s *mfaService) getDisplayName(config *MFAConfigData) string {
	// switch config.Method {
	// case MethodTOTP:
	//
	//	return "Authenticator App"
	//
	// case MethodSMS:
	//
	//	if config.SecretEncrypted != nil {
	//		decrypted, err := s.encryptor.Decrypt(config.SecretEncrypted)
	//		if err == nil {
	//			return "SMS to " + s.maskPhoneNumber(string(decrypted))
	//		}
	//	}
	//	return "SMS"
	//
	// case MethodEmail:
	//
	//	if config.SecretEncrypted != nil {
	//		decrypted, err := s.encryptor.Decrypt(config.SecretEncrypted)
	//		if err == nil {
	//			return "Email to " + s.maskEmail(string(decrypted))
	//		}
	//	}
	//	return "Email"
	//
	// case MethodWebAuthn:
	//
	//	if config.SecretEncrypted != nil {
	//		decrypted, err := s.encryptor.Decrypt(config.SecretEncrypted)
	//		if err == nil {
	//			var credential WebAuthnCredential
	//			if json.Unmarshal(decrypted, &credential) == nil {
	//				return credential.DisplayName
	//			}
	//		}
	//	}
	//	return "Security Key"
	//
	// default:
	//
	//	return config.Methodpted, err := s.encryptor.Decrypt(config.SecretEncrypted)
	//		if err == nil {
	//			return "Email to " + s.maskEmail(string(decrypted))
	//		}
	//	}
	//	return "Email"
	//
	// default:
	//
	//		return strings.ToUpper(config.Method)
	//	}
	return "" //TODO: uncomment
}

// Validation methods
func (s *mfaService) validateSetupTOTPRequest(req *SetupTOTPRequest) error {
	if req.UserID == "" {
		return errors.New(errors.ErrorTypeValidation, "MISSING_USER_ID", "User ID is required")
	}
	if _, err := uuid.Parse(req.UserID); err != nil {
		return errors.New(errors.ErrorTypeValidation, "INVALID_USER_ID", "Invalid user ID format")
	}
	return nil
}

func (s *mfaService) validateVerifyTOTPRequest(req *VerifyTOTPRequest) error {
	if req.Code == "" {
		return errors.New(errors.ErrorTypeValidation, "MISSING_CODE", "Verification code is required")
	}
	if len(req.Code) != TOTPCodeLength {
		return errors.New(errors.ErrorTypeValidation, "INVALID_CODE_LENGTH", "Invalid code length")
	}
	if req.SetupToken == "" && req.UserID == "" && req.ConfigID == "" {
		return errors.New(errors.ErrorTypeValidation, "MISSING_IDENTIFIER", "Setup token, user ID, or config ID is required")
	}
	return nil
}

func (s *mfaService) validateSetupSMSRequest(req *SetupSMSRequest) error {
	if req.UserID == "" {
		return errors.New(errors.ErrorTypeValidation, "MISSING_USER_ID", "User ID is required")
	}
	if _, err := uuid.Parse(req.UserID); err != nil {
		return errors.New(errors.ErrorTypeValidation, "INVALID_USER_ID", "Invalid user ID format")
	}
	if req.PhoneNumber == "" {
		return errors.New(errors.ErrorTypeValidation, "MISSING_PHONE_NUMBER", "Phone number is required")
	}
	return nil
}

func (s *mfaService) validateSendSMSCodeRequest(req *SendSMSCodeRequest) error {
	if req.UserID == "" && req.ConfigID == "" {
		return errors.New(errors.ErrorTypeValidation, "MISSING_IDENTIFIER", "User ID or config ID is required")
	}
	if req.UserID != "" {
		if _, err := uuid.Parse(req.UserID); err != nil {
			return errors.New(errors.ErrorTypeValidation, "INVALID_USER_ID", "Invalid user ID format")
		}
	}
	if req.ConfigID != "" {
		if _, err := uuid.Parse(req.ConfigID); err != nil {
			return errors.New(errors.ErrorTypeValidation, "INVALID_CONFIG_ID", "Invalid config ID format")
		}
	}
	return nil
}

func (s *mfaService) validateVerifySMSRequest(req *VerifySMSRequest) error {
	if req.Code == "" {
		return errors.New(errors.ErrorTypeValidation, "MISSING_CODE", "Verification code is required")
	}
	if len(req.Code) != SMSCodeLength {
		return errors.New(errors.ErrorTypeValidation, "INVALID_CODE_LENGTH", "Invalid code length")
	}
	return nil
}

func (s *mfaService) validateSetupEmailRequest(req *SetupEmailRequest) error {
	if req.UserID == "" {
		return errors.New(errors.ErrorTypeValidation, "MISSING_USER_ID", "User ID is required")
	}
	if _, err := uuid.Parse(req.UserID); err != nil {
		return errors.New(errors.ErrorTypeValidation, "INVALID_USER_ID", "Invalid user ID format")
	}
	if req.Email == "" {
		return errors.New(errors.ErrorTypeValidation, "MISSING_EMAIL", "Email is required")
	}
	return nil
}

func (s *mfaService) validateSendEmailCodeRequest(req *SendEmailCodeRequest) error {
	if req.UserID == "" && req.ConfigID == "" {
		return errors.New(errors.ErrorTypeValidation, "MISSING_IDENTIFIER", "User ID or config ID is required")
	}
	if req.UserID != "" {
		if _, err := uuid.Parse(req.UserID); err != nil {
			return errors.New(errors.ErrorTypeValidation, "INVALID_USER_ID", "Invalid user ID format")
		}
	}
	if req.ConfigID != "" {
		if _, err := uuid.Parse(req.ConfigID); err != nil {
			return errors.New(errors.ErrorTypeValidation, "INVALID_CONFIG_ID", "Invalid config ID format")
		}
	}
	return nil
}

func (s *mfaService) validateVerifyEmailRequest(req *VerifyEmailRequest) error {
	if req.Code == "" {
		return errors.New(errors.ErrorTypeValidation, "MISSING_CODE", "Verification code is required")
	}
	if len(req.Code) != EmailCodeLength {
		return errors.New(errors.ErrorTypeValidation, "INVALID_CODE_LENGTH", "Invalid code length")
	}
	return nil
}

func (s *mfaService) validateDisableMFARequest(req *DisableMFARequest) error {
	if req.UserID == "" {
		return errors.New(errors.ErrorTypeValidation, "MISSING_USER_ID", "User ID is required")
	}
	if _, err := uuid.Parse(req.UserID); err != nil {
		return errors.New(errors.ErrorTypeValidation, "INVALID_USER_ID", "Invalid user ID format")
	}
	if req.ConfigID == "" {
		return errors.New(errors.ErrorTypeValidation, "MISSING_CONFIG_ID", "Config ID is required")
	}
	if _, err := uuid.Parse(req.ConfigID); err != nil {
		return errors.New(errors.ErrorTypeValidation, "INVALID_CONFIG_ID", "Invalid config ID format")
	}
	if req.Method == "" {
		return errors.New(errors.ErrorTypeValidation, "MISSING_METHOD", "Method is required")
	}
	if req.Method != MethodTOTP && req.Method != MethodSMS && req.Method != MethodEmail {
		return errors.New(errors.ErrorTypeValidation, "INVALID_METHOD", "Invalid MFA method")
	}
	return nil
}

func (s *mfaService) validateGenerateBackupCodesRequest(req *GenerateBackupCodesRequest) error {
	if req.UserID == "" {
		return errors.New(errors.ErrorTypeValidation, "MISSING_USER_ID", "User ID is required")
	}
	if _, err := uuid.Parse(req.UserID); err != nil {
		return errors.New(errors.ErrorTypeValidation, "INVALID_USER_ID", "Invalid user ID format")
	}
	if req.ConfigID == "" {
		return errors.New(errors.ErrorTypeValidation, "MISSING_CONFIG_ID", "Config ID is required")
	}
	if _, err := uuid.Parse(req.ConfigID); err != nil {
		return errors.New(errors.ErrorTypeValidation, "INVALID_CONFIG_ID", "Invalid config ID format")
	}
	return nil
}

func (s *mfaService) validateVerifyBackupCodeRequest(req *VerifyBackupCodeRequest) error {
	if req.UserID == "" {
		return errors.New(errors.ErrorTypeValidation, "MISSING_USER_ID", "User ID is required")
	}
	if _, err := uuid.Parse(req.UserID); err != nil {
		return errors.New(errors.ErrorTypeValidation, "INVALID_USER_ID", "Invalid user ID format")
	}
	if req.BackupCode == "" {
		return errors.New(errors.ErrorTypeValidation, "MISSING_BACKUP_CODE", "Backup code is required")
	}
	if len(req.BackupCode) != BackupCodeLength {
		return errors.New(errors.ErrorTypeValidation, "INVALID_BACKUP_CODE_LENGTH", "Invalid backup code length")
	}
	return nil
}

// WebAuthn user adapter that implements webauthn.User interface
type webAuthnUser struct {
	id          []byte
	name        string
	displayName string
	credentials []webauthn.Credential
}

func (u *webAuthnUser) WebAuthnID() []byte {
	return u.id
}

func (u *webAuthnUser) WebAuthnName() string {
	return u.name
}

func (u *webAuthnUser) WebAuthnDisplayName() string {
	return u.displayName
}

func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

func (u *webAuthnUser) WebAuthnIcon() string {
	return ""
}

// WebAuthn Methods Implementation

// SetupWebAuthn initiates WebAuthn credential registration
func (s *mfaService) SetupWebAuthn(ctx context.Context, req *SetupWebAuthnRequest) (*SetupWebAuthnResponse, error) {
	// Check if WebAuthn is enabled
	if s.webAuthn == nil {
		return nil, errors.New(errors.ErrorTypeInternal, "WEBAUTHN_NOT_CONFIGURED", "WebAuthn is not properly configured")
	}

	// Validate request
	if err := s.validateSetupWebAuthnRequest(req); err != nil {
		return nil, err
	}

	// Check if user exists
	user, err := s.userRepo.GetUserByID(ctx, req.UserID)
	if err != nil || user == nil {
		return nil, ErrUserNotFound
	}

	if user.AccountLocked {
		return nil, ErrUserAccountLocked
	}

	// Check if WebAuthn is already configured for this user
	existingConfig, _ := s.mfaRepo.GetUserMFAByMethod(ctx, req.UserID, MethodWebAuthn)
	if existingConfig != nil && existingConfig.Enabled {
		return nil, ErrMFAAlreadyExists.WithDetails("WebAuthn is already configured for this user")
	}

	// Get existing credentials for this user
	existingCredentials, err := s.getWebAuthnCredentials(ctx, req.UserID)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "CREDENTIAL_RETRIEVAL_FAILED", "Failed to retrieve existing credentials")
	}

	// Create WebAuthn user
	displayName := req.DisplayName
	if displayName == "" {
		displayName = user.Email
	}

	webAuthnUser := &webAuthnUser{
		id:          []byte(req.UserID),
		name:        user.Email,
		displayName: displayName,
		credentials: existingCredentials,
	}

	// Begin registration
	creation, sessionData, err := s.webAuthn.BeginRegistration(webAuthnUser)
	if err != nil {
		return nil, ErrWebAuthnCredentialCreation.WithCause(err)
	}

	// Generate backup codes
	backupCodes, err := s.generateBackupCodes()
	if err != nil {
		return nil, ErrBackupCodeGenerationFailed.WithCause(err)
	}

	// Encrypt backup codes
	backupCodesJSON, _ := json.Marshal(backupCodes)
	encryptedBackupCodes, err := s.encryptor.Encrypt(backupCodesJSON)
	if err != nil {
		return nil, ErrEncryptionFailed.WithCause(err)
	}

	// Create MFA config (initially disabled until verified)
	configData := &MFAConfigData{
		UserID:               req.UserID,
		Method:               MethodWebAuthn,
		SecretEncrypted:      nil, // Will be set after credential creation
		BackupCodesEncrypted: encryptedBackupCodes,
		Enabled:              false, // Will be enabled after verification
	}

	// Save to database
	createdConfig, err := s.mfaRepo.CreateMFAConfig(ctx, configData)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "MFA_CONFIG_CREATION_FAILED", "Failed to create MFA configuration")
	}

	// Store session data in cache
	sessionDataJSON, _ := json.Marshal(sessionData)
	cacheKey := fmt.Sprintf("%s%s:%s", CacheKeyWebAuthnSetup, req.UserID, createdConfig.ID)
	if err := s.cacheService.Set(ctx, cacheKey, sessionDataJSON, int64(WebAuthnTimeout/1000)); err != nil {
		return nil, ErrCacheOperationFailed.WithCause(err)
	}

	// Convert creation options to our response format
	credentialCreation := s.convertCredentialCreation(creation)

	return &SetupWebAuthnResponse{
		ConfigID:           uuid.MustParse(createdConfig.ID),
		CredentialCreation: credentialCreation,
		BackupCodes:        backupCodes,
		Message:            "WebAuthn setup initiated. Please complete the credential creation process.",
	}, nil
}

// FinishWebAuthnSetup completes WebAuthn credential registration
// FinishWebAuthnSetup completes WebAuthn credential registration
func (s *mfaService) FinishWebAuthnSetup(ctx context.Context, req *FinishWebAuthnSetupRequest) (*FinishWebAuthnSetupResponse, error) {
	// Check if WebAuthn is enabled
	if s.webAuthn == nil {
		return nil, errors.New(errors.ErrorTypeInternal, "WEBAUTHN_NOT_CONFIGURED", "WebAuthn is not properly configured")
	}

	// Validate request
	if err := s.validateFinishWebAuthnSetupRequest(req); err != nil {
		return nil, err
	}

	// Get session data from cache
	cacheKey := fmt.Sprintf("%s%s:%s", CacheKeyWebAuthnSetup, req.UserID, req.ConfigID)
	cachedData, err := s.cacheService.Get(ctx, cacheKey)
	if err != nil {
		return nil, ErrWebAuthnSetupNotFound
	}

	var sessionData webauthn.SessionData
	// Fix: Type assertion with error checking
	cachedBytes, ok := cachedData.([]byte)
	if !ok {
		return nil, errors.New(errors.ErrorTypeInternal, "INVALID_CACHE_DATA", "Cached session data is not in expected format")
	}

	if err := json.Unmarshal(cachedBytes, &sessionData); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "SESSION_DATA_UNMARSHAL_FAILED", "Failed to unmarshal session data")
	}

	// Get user data
	user, err := s.userRepo.GetUserByID(ctx, req.UserID)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "USER_RETRIEVAL_FAILED", "Failed to retrieve user")
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	// Get existing credentials for this user
	existingCredentials, err := s.getWebAuthnCredentials(ctx, req.UserID)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "CREDENTIAL_RETRIEVAL_FAILED", "Failed to retrieve existing credentials")
	}

	// Create WebAuthn user
	webAuthnUser := &webAuthnUser{
		id:          []byte(req.UserID),
		name:        user.Email,
		displayName: user.Email,
		credentials: existingCredentials,
	}

	// Convert the credential response to JSON and create HTTP request
	credentialResponseJSON, err := json.Marshal(req.CredentialResponse)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "CREDENTIAL_RESPONSE_MARSHAL_FAILED", "Failed to marshal credential response")
	}

	// Create HTTP request with the credential response data
	httpReq, err := http.NewRequestWithContext(ctx, "POST", "/", strings.NewReader(string(credentialResponseJSON)))
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "HTTP_REQUEST_CREATION_FAILED", "Failed to create HTTP request")
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// Finish registration
	credential, err := s.webAuthn.FinishRegistration(webAuthnUser, sessionData, httpReq)
	if err != nil {
		return nil, ErrWebAuthnCredentialVerification.WithCause(err)
	}

	// Store the credential
	credentialData := &WebAuthnCredential{
		ID:              credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		Authenticator: AuthenticatorData{
			AAGUID:       credential.Authenticator.AAGUID,
			SignCount:    credential.Authenticator.SignCount,
			CloneWarning: credential.Authenticator.CloneWarning,
		},
		DisplayName: "Security Key",
	}

	// Encrypt and store the credential
	credentialJSON, err := json.Marshal(credentialData)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "CREDENTIAL_MARSHAL_FAILED", "Failed to marshal credential data")
	}

	encryptedCredential, err := s.encryptor.Encrypt(credentialJSON)
	if err != nil {
		return nil, ErrEncryptionFailed.WithCause(err)
	}

	// Update MFA config with credential and enable it
	enabled := true
	updateData := &UpdateMFAConfigData{
		SecretEncrypted: encryptedCredential,
		Enabled:         &enabled,
	}

	_, err = s.mfaRepo.UpdateMFAConfig(ctx, req.ConfigID, updateData)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "MFA_CONFIG_UPDATE_FAILED", "Failed to update MFA configuration")
	}

	// Clean up setup session
	if err := s.cacheService.Delete(ctx, cacheKey); err != nil {
		// Log the error but don't fail the operation
		// You might want to use your logging system here
		fmt.Printf("Warning: Failed to delete cache key %s: %v\n", cacheKey, err)
	}

	return &FinishWebAuthnSetupResponse{
		Success:      true,
		ConfigID:     req.ConfigID,
		Message:      "WebAuthn credential registered successfully",
		CredentialID: base64.URLEncoding.EncodeToString(credential.ID),
	}, nil
}

// BeginWebAuthnLogin initiates WebAuthn authentication
func (s *mfaService) BeginWebAuthnLogin(ctx context.Context, req *BeginWebAuthnLoginRequest) (*BeginWebAuthnLoginResponse, error) {
	// Check if WebAuthn is enabled
	if s.webAuthn == nil {
		return nil, errors.New(errors.ErrorTypeInternal, "WEBAUTHN_NOT_CONFIGURED", "WebAuthn is not properly configured")
	}

	// Validate request
	if err := s.validateBeginWebAuthnLoginRequest(req); err != nil {
		return nil, err
	}

	// Get MFA config
	var config *MFAConfigData
	var err error

	if req.ConfigID != "" {
		config, err = s.mfaRepo.GetMFAConfigByID(ctx, req.ConfigID)
	} else if req.UserID != "" {
		config, err = s.mfaRepo.GetUserMFAByMethod(ctx, req.UserID, MethodWebAuthn)
	} else {
		return nil, errors.New(errors.ErrorTypeValidation, "MISSING_IDENTIFIER", "Either user_id or config_id must be provided")
	}

	if err != nil || config == nil {
		return nil, ErrMFANotFound
	}

	if !config.Enabled {
		return nil, ErrMFANotEnabled
	}

	// Get user data
	user, err := s.userRepo.GetUserByID(ctx, config.UserID)
	if err != nil || user == nil {
		return nil, ErrUserNotFound
	}

	// Get WebAuthn credentials for this user
	credentials, err := s.getWebAuthnCredentials(ctx, config.UserID)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "CREDENTIAL_RETRIEVAL_FAILED", "Failed to retrieve credentials")
	}

	// Create WebAuthn user
	webAuthnUser := &webAuthnUser{
		id:          []byte(config.UserID),
		name:        user.Email,
		displayName: user.Email,
		credentials: credentials,
	}

	// Begin login
	assertion, sessionData, err := s.webAuthn.BeginLogin(webAuthnUser)
	if err != nil {
		return nil, ErrWebAuthnCredentialVerification.WithCause(err)
	}

	// Store session data in cache
	sessionDataJSON, _ := json.Marshal(sessionData)
	cacheKey := fmt.Sprintf("%s%s:%s", CacheKeyWebAuthnLogin, config.UserID, config.ID)
	if err := s.cacheService.Set(ctx, cacheKey, sessionDataJSON, int64(WebAuthnTimeout/1000)); err != nil {
		return nil, ErrCacheOperationFailed.WithCause(err)
	}

	// Convert assertion to our response format
	credentialAssertion := s.convertCredentialAssertion(assertion)

	return &BeginWebAuthnLoginResponse{
		CredentialAssertion: credentialAssertion,
		Message:             "WebAuthn authentication challenge generated",
	}, nil
}

// FinishWebAuthnLogin completes WebAuthn authentication
func (s *mfaService) FinishWebAuthnLogin(ctx context.Context, req *FinishWebAuthnLoginRequest) (*FinishWebAuthnLoginResponse, error) {
	// Check if WebAuthn is enabled
	if s.webAuthn == nil {
		return nil, errors.New(errors.ErrorTypeInternal, "WEBAUTHN_NOT_CONFIGURED", "WebAuthn is not properly configured")
	}

	// Validate request
	if err := s.validateFinishWebAuthnLoginRequest(req); err != nil {
		return nil, err
	}

	// Get MFA config
	var config *MFAConfigData
	var err error
	if req.ConfigID != "" {
		config, err = s.mfaRepo.GetMFAConfigByID(ctx, req.ConfigID)
	} else if req.UserID != "" {
		config, err = s.mfaRepo.GetUserMFAByMethod(ctx, req.UserID, MethodWebAuthn)
	} else {
		return nil, errors.New(errors.ErrorTypeValidation, "MISSING_IDENTIFIER", "Either user_id or config_id must be provided")
	}

	if err != nil || config == nil {
		return nil, ErrMFANotFound
	}
	if !config.Enabled {
		return nil, ErrMFANotEnabled
	}

	// Get session data from cache
	cacheKey := fmt.Sprintf("%s%s:%s", CacheKeyWebAuthnLogin, config.UserID, config.ID)
	cachedData, err := s.cacheService.Get(ctx, cacheKey)
	if err != nil {
		return nil, ErrWebAuthnLoginNotFound
	}

	var sessionData webauthn.SessionData
	// Fix: Type assertion with error checking
	cachedBytes, ok := cachedData.([]byte)
	if !ok {
		return nil, errors.New(errors.ErrorTypeInternal, "INVALID_CACHE_DATA", "Cached session data is not in expected format")
	}

	if err := json.Unmarshal(cachedBytes, &sessionData); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "SESSION_DATA_UNMARSHAL_FAILED", "Failed to unmarshal session data")
	}

	// Get user data
	user, err := s.userRepo.GetUserByID(ctx, config.UserID)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "USER_RETRIEVAL_FAILED", "Failed to retrieve user")
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	// Get WebAuthn credentials for this user
	credentials, err := s.getWebAuthnCredentials(ctx, config.UserID)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "CREDENTIAL_RETRIEVAL_FAILED", "Failed to retrieve credentials")
	}

	// Create WebAuthn user
	webAuthnUser := &webAuthnUser{
		id:          []byte(config.UserID),
		name:        user.Email,
		displayName: user.Email,
		credentials: credentials,
	}

	// Convert the credential response to JSON and create HTTP request
	credentialResponseJSON, err := json.Marshal(req.CredentialResponse)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "CREDENTIAL_RESPONSE_MARSHAL_FAILED", "Failed to marshal credential response")
	}

	// Create HTTP request with the credential response data
	httpReq, err := http.NewRequestWithContext(ctx, "POST", "/", strings.NewReader(string(credentialResponseJSON)))
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "HTTP_REQUEST_CREATION_FAILED", "Failed to create HTTP request")
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// Finish login
	credential, err := s.webAuthn.FinishLogin(webAuthnUser, sessionData, httpReq)
	if err != nil {
		return nil, ErrWebAuthnCredentialVerification.WithCause(err)
	}

	// Update the credential with new sign count
	err = s.updateWebAuthnCredential(ctx, config.UserID, credential)
	if err != nil {
		// Log error but don't fail the authentication
		// The authentication was successful, we just couldn't update the sign count
		fmt.Printf("Warning: Failed to update WebAuthn credential sign count: %v\n", err)
	}

	// Update last used timestamp
	updateData := &UpdateMFAConfigData{
		UpdateLastUsed: true,
	}
	if _, err := s.mfaRepo.UpdateMFAConfig(ctx, config.ID, updateData); err != nil {
		// Log the error but don't fail the authentication
		fmt.Printf("Warning: Failed to update MFA config last used timestamp: %v\n", err)
	}

	// Clean up login session
	if err := s.cacheService.Delete(ctx, cacheKey); err != nil {
		// Log the error but don't fail the operation
		fmt.Printf("Warning: Failed to delete cache key %s: %v\n", cacheKey, err)
	}

	return &FinishWebAuthnLoginResponse{
		Valid:    true,
		ConfigID: config.ID,
		Message:  "WebAuthn authentication successful",
	}, nil
}

// WebAuthn helper methods

func (s *mfaService) getWebAuthnCredentials(ctx context.Context, userID string) ([]webauthn.Credential, error) {
	// Get all WebAuthn configs for the user
	configs, err := s.mfaRepo.GetUserMFAConfigs(ctx, userID)
	if err != nil {
		return nil, err
	}

	var credentials []webauthn.Credential
	for _, config := range configs {
		if config.Method != MethodWebAuthn || !config.Enabled || config.SecretEncrypted == nil {
			continue
		}

		// Decrypt credential
		decryptedCredential, err := s.encryptor.Decrypt(config.SecretEncrypted)
		if err != nil {
			continue
		}

		var credentialData WebAuthnCredential
		if err := json.Unmarshal(decryptedCredential, &credentialData); err != nil {
			continue
		}

		// Convert to webauthn.Credential
		credential := webauthn.Credential{
			ID:              credentialData.ID,
			PublicKey:       credentialData.PublicKey,
			AttestationType: credentialData.AttestationType,
			Authenticator: webauthn.Authenticator{
				AAGUID:       credentialData.Authenticator.AAGUID,
				SignCount:    credentialData.Authenticator.SignCount,
				CloneWarning: credentialData.Authenticator.CloneWarning,
			},
		}

		credentials = append(credentials, credential)
	}

	return credentials, nil
}

func (s *mfaService) convertCredentialCreation(creation *protocol.CredentialCreation) CredentialCreation {
	return CredentialCreation{
		PublicKey: PublicKeyCredentialCreationOptions{
			Challenge: creation.Response.Challenge,
			RP: RelyingParty{
				ID:   creation.Response.RelyingParty.ID,
				Name: creation.Response.RelyingParty.Name,
			},
			User: UserEntity{
				ID:          creation.Response.User.ID.([]byte),
				Name:        creation.Response.User.Name,
				DisplayName: creation.Response.User.DisplayName,
			},
			PubKeyCredParams: s.convertPubKeyCredParams(creation.Response.Parameters),
			AuthenticatorSelection: AuthenticatorSelectionCriteria{
				AuthenticatorAttachment: string(creation.Response.AuthenticatorSelection.AuthenticatorAttachment),
				RequireResidentKey:      *creation.Response.AuthenticatorSelection.RequireResidentKey,
				UserVerification:        string(creation.Response.AuthenticatorSelection.UserVerification),
			},
			Timeout:            int(creation.Response.Timeout),
			ExcludeCredentials: s.convertCredentialDescriptors(creation.Response.CredentialExcludeList),
		},
	}
}

func (s *mfaService) convertCredentialAssertion(assertion *protocol.CredentialAssertion) CredentialAssertion {
	return CredentialAssertion{
		PublicKey: PublicKeyCredentialRequestOptions{
			Challenge:        assertion.Response.Challenge,
			Timeout:          int(assertion.Response.Timeout),
			RPID:             assertion.Response.RelyingPartyID,
			AllowCredentials: s.convertCredentialDescriptors(assertion.Response.AllowedCredentials),
			UserVerification: string(assertion.Response.UserVerification),
		},
	}
}

func (s *mfaService) convertPubKeyCredParams(params []protocol.CredentialParameter) []PublicKeyCredentialParameters {
	result := make([]PublicKeyCredentialParameters, len(params))
	for i, param := range params {
		result[i] = PublicKeyCredentialParameters{
			Type: string(param.Type),
			Alg:  int(param.Algorithm),
		}
	}
	return result
}

func (s *mfaService) convertCredentialDescriptors(descriptors []protocol.CredentialDescriptor) []PublicKeyCredentialDescriptor {
	result := make([]PublicKeyCredentialDescriptor, len(descriptors))
	for i, desc := range descriptors {
		transports := make([]string, len(desc.Transport))
		for j, transport := range desc.Transport {
			transports[j] = string(transport)
		}
		result[i] = PublicKeyCredentialDescriptor{
			Type:       string(desc.Type),
			ID:         desc.CredentialID,
			Transports: transports,
		}
	}
	return result
}

// func (s *mfaService) parseCredentialCreationResponse(response *CredentialCreationResponse) (*protocol.ParsedCredentialCreationData, error) {
// 	// Convert our response format to the WebAuthn library format
// 	parsedResponse := &protocol.ParsedCredentialCreationData{
// 		ID:                     response.ID,
// 		RawID:                  response.RawID,
// 		Type:                   response.Type,
// 		ClientExtensionResults: protocol.AuthenticationExtensionsClientOutputs{},
// 		Response: protocol.AuthenticatorAttestationResponse{
// 			AuthenticatorResponse: protocol.AuthenticatorResponse{
// 				ClientDataJSON: response.Response.ClientDataJSON,
// 			},
// 			AttestationObject: response.Response.AttestationObject,
// 		},
// 	}

// 	return parsedResponse, nil
// }

// func (s *mfaService) parseCredentialAssertionResponse(response *CredentialAssertionResponse) (*protocol.ParsedCredentialAssertionData, error) {
// 	// Convert our response format to the WebAuthn library format
// 	parsedResponse := &protocol.ParsedCredentialAssertionData{
// 		ID:                     response.ID,
// 		RawID:                  response.RawID,
// 		Type:                   response.Type,
// 		ClientExtensionResults: protocol.AuthenticationExtensionsClientOutputs{},
// 		Response: protocol.AuthenticatorAssertionResponse{
// 			AuthenticatorResponse: protocol.AuthenticatorResponse{
// 				ClientDataJSON: response.Response.ClientDataJSON,
// 			},
// 			AuthenticatorData: response.Response.AuthenticatorData,
// 			Signature:         response.Response.Signature,
// 			UserHandle:        response.Response.UserHandle,
// 		},
// 	}

// 	return parsedResponse, nil
// }

func (s *mfaService) updateWebAuthnCredential(ctx context.Context, userID string, credential *webauthn.Credential) error {
	// Get all WebAuthn configs for the user
	configs, err := s.mfaRepo.GetUserMFAConfigs(ctx, userID)
	if err != nil {
		return err
	}

	// Find the matching credential and update it
	for _, config := range configs {
		if config.Method != MethodWebAuthn || !config.Enabled || config.SecretEncrypted == nil {
			continue
		}

		// Decrypt credential
		decryptedCredential, err := s.encryptor.Decrypt(config.SecretEncrypted)
		if err != nil {
			continue
		}

		var credentialData WebAuthnCredential
		if err := json.Unmarshal(decryptedCredential, &credentialData); err != nil {
			continue
		}

		// Check if this is the matching credential
		if subtle.ConstantTimeCompare(credentialData.ID, credential.ID) == 1 {
			// Update the credential data
			credentialData.Authenticator.SignCount = credential.Authenticator.SignCount
			credentialData.Authenticator.CloneWarning = credential.Authenticator.CloneWarning

			// Re-encrypt and store
			updatedCredentialJSON, _ := json.Marshal(credentialData)
			encryptedUpdatedCredential, err := s.encryptor.Encrypt(updatedCredentialJSON)
			if err != nil {
				return err
			}

			updateData := &UpdateMFAConfigData{
				SecretEncrypted: encryptedUpdatedCredential,
			}

			_, err = s.mfaRepo.UpdateMFAConfig(ctx, config.ID, updateData)
			return err
		}
	}

	return errors.New(errors.ErrorTypeNotFound, "CREDENTIAL_NOT_FOUND", "WebAuthn credential not found")
}

// WebAuthn validation methods

func (s *mfaService) validateSetupWebAuthnRequest(req *SetupWebAuthnRequest) error {
	if req == nil {
		return errors.New(errors.ErrorTypeValidation, "INVALID_REQUEST", "Request cannot be nil")
	}

	if _, err := uuid.Parse(req.UserID); err != nil {
		return errors.New(errors.ErrorTypeValidation, "INVALID_USER_ID", "Invalid user ID format")
	}

	return nil
}

func (s *mfaService) validateFinishWebAuthnSetupRequest(req *FinishWebAuthnSetupRequest) error {
	if req == nil {
		return errors.New(errors.ErrorTypeValidation, "INVALID_REQUEST", "Request cannot be nil")
	}

	if _, err := uuid.Parse(req.UserID); err != nil {
		return errors.New(errors.ErrorTypeValidation, "INVALID_USER_ID", "Invalid user ID format")
	}

	if _, err := uuid.Parse(req.ConfigID); err != nil {
		return errors.New(errors.ErrorTypeValidation, "INVALID_CONFIG_ID", "Invalid config ID format")
	}

	if req.CredentialResponse.ID == "" {
		return errors.New(errors.ErrorTypeValidation, "MISSING_CREDENTIAL_ID", "Credential ID is required")
	}

	if len(req.CredentialResponse.RawID) == 0 {
		return errors.New(errors.ErrorTypeValidation, "MISSING_RAW_ID", "Raw credential ID is required")
	}

	if len(req.CredentialResponse.Response.ClientDataJSON) == 0 {
		return errors.New(errors.ErrorTypeValidation, "MISSING_CLIENT_DATA", "Client data JSON is required")
	}

	if len(req.CredentialResponse.Response.AttestationObject) == 0 {
		return errors.New(errors.ErrorTypeValidation, "MISSING_ATTESTATION", "Attestation object is required")
	}

	return nil
}

func (s *mfaService) validateBeginWebAuthnLoginRequest(req *BeginWebAuthnLoginRequest) error {
	if req == nil {
		return errors.New(errors.ErrorTypeValidation, "INVALID_REQUEST", "Request cannot be nil")
	}

	if req.UserID == "" && req.ConfigID == "" {
		return errors.New(errors.ErrorTypeValidation, "MISSING_IDENTIFIER", "Either user_id or config_id must be provided")
	}

	if req.UserID != "" {
		if _, err := uuid.Parse(req.UserID); err != nil {
			return errors.New(errors.ErrorTypeValidation, "INVALID_USER_ID", "Invalid user ID format")
		}
	}

	if req.ConfigID != "" {
		if _, err := uuid.Parse(req.ConfigID); err != nil {
			return errors.New(errors.ErrorTypeValidation, "INVALID_CONFIG_ID", "Invalid config ID format")
		}
	}

	return nil
}

func (s *mfaService) validateFinishWebAuthnLoginRequest(req *FinishWebAuthnLoginRequest) error {
	if req == nil {
		return errors.New(errors.ErrorTypeValidation, "INVALID_REQUEST", "Request cannot be nil")
	}

	if req.UserID == "" && req.ConfigID == "" {
		return errors.New(errors.ErrorTypeValidation, "MISSING_IDENTIFIER", "Either user_id or config_id must be provided")
	}

	if req.UserID != "" {
		if _, err := uuid.Parse(req.UserID); err != nil {
			return errors.New(errors.ErrorTypeValidation, "INVALID_USER_ID", "Invalid user ID format")
		}
	}

	if req.ConfigID != "" {
		if _, err := uuid.Parse(req.ConfigID); err != nil {
			return errors.New(errors.ErrorTypeValidation, "INVALID_CONFIG_ID", "Invalid config ID format")
		}
	}

	if req.CredentialResponse.ID == "" {
		return errors.New(errors.ErrorTypeValidation, "MISSING_CREDENTIAL_ID", "Credential ID is required")
	}

	if len(req.CredentialResponse.RawID) == 0 {
		return errors.New(errors.ErrorTypeValidation, "MISSING_RAW_ID", "Raw credential ID is required")
	}

	if len(req.CredentialResponse.Response.ClientDataJSON) == 0 {
		return errors.New(errors.ErrorTypeValidation, "MISSING_CLIENT_DATA", "Client data JSON is required")
	}

	if len(req.CredentialResponse.Response.AuthenticatorData) == 0 {
		return errors.New(errors.ErrorTypeValidation, "MISSING_AUTHENTICATOR_DATA", "Authenticator data is required")
	}

	if len(req.CredentialResponse.Response.Signature) == 0 {
		return errors.New(errors.ErrorTypeValidation, "MISSING_SIGNATURE", "Signature is required")
	}

	return nil
}
