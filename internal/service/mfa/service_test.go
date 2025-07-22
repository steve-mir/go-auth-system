package mfa

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/steve-mir/go-auth-system/internal/config"
	"github.com/steve-mir/go-auth-system/internal/errors"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

// Mock implementations
type MockMFARepository struct {
	mock.Mock
}

func (m *MockMFARepository) CreateMFAConfig(ctx context.Context, config *MFAConfigData) (*MFAConfigData, error) {
	args := m.Called(ctx, config)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*MFAConfigData), args.Error(1)
}

func (m *MockMFARepository) GetMFAConfigByID(ctx context.Context, id string) (*MFAConfigData, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*MFAConfigData), args.Error(1)
}

func (m *MockMFARepository) GetUserMFAByMethod(ctx context.Context, userID, method string) (*MFAConfigData, error) {
	args := m.Called(ctx, userID, method)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*MFAConfigData), args.Error(1)
}

func (m *MockMFARepository) GetUserMFAConfigs(ctx context.Context, userID string) ([]*MFAConfigData, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*MFAConfigData), args.Error(1)
}

func (m *MockMFARepository) GetEnabledMFAMethods(ctx context.Context, userID string) ([]string, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockMFARepository) UpdateMFAConfig(ctx context.Context, id string, config *UpdateMFAConfigData) (*MFAConfigData, error) {
	args := m.Called(ctx, id, config)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*MFAConfigData), args.Error(1)
}

func (m *MockMFARepository) EnableMFA(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockMFARepository) DisableMFA(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockMFARepository) DeleteMFAConfig(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockMFARepository) CountUserMFAMethods(ctx context.Context, userID string) (int64, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).(int64), args.Error(1)
}

type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) GetUserByID(ctx context.Context, userID string) (*UserData, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*UserData), args.Error(1)
}

type MockSMSService struct {
	mock.Mock
}

func (m *MockSMSService) SendSMS(ctx context.Context, phoneNumber, message string) error {
	args := m.Called(ctx, phoneNumber, message)
	return args.Error(0)
}

type MockEmailService struct {
	mock.Mock
}

func (m *MockEmailService) SendEmail(ctx context.Context, to, subject, body string) error {
	args := m.Called(ctx, to, subject, body)
	return args.Error(0)
}

type MockCacheService struct {
	mock.Mock
}

func (m *MockCacheService) Set(ctx context.Context, key string, value interface{}, expiration int64) error {
	args := m.Called(ctx, key, value, expiration)
	return args.Error(0)
}

func (m *MockCacheService) Get(ctx context.Context, key string) (interface{}, error) {
	args := m.Called(ctx, key)
	return args.Get(0), args.Error(1)
}

func (m *MockCacheService) Delete(ctx context.Context, key string) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

type MockEncryptor struct {
	mock.Mock
}

func (m *MockEncryptor) Encrypt(data []byte) ([]byte, error) {
	args := m.Called(data)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockEncryptor) Decrypt(data []byte) ([]byte, error) {
	args := m.Called(data)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

// Test Suite
type MFAServiceTestSuite struct {
	suite.Suite
	service      MFAService
	mfaRepo      *MockMFARepository
	userRepo     *MockUserRepository
	smsService   *MockSMSService
	emailService *MockEmailService
	cacheService *MockCacheService
	encryptor    *MockEncryptor
	config       *config.Config
	ctx          context.Context
}

func (suite *MFAServiceTestSuite) SetupTest() {
	suite.mfaRepo = &MockMFARepository{}
	suite.userRepo = &MockUserRepository{}
	suite.smsService = &MockSMSService{}
	suite.emailService = &MockEmailService{}
	suite.cacheService = &MockCacheService{}
	suite.encryptor = &MockEncryptor{}
	suite.ctx = context.Background()

	suite.config = &config.Config{
		Features: config.FeaturesConfig{
			MFA: config.MFAConfig{
				TOTP: config.TOTPConfig{
					Issuer: "Test App",
				},
				Email: config.EmailConfig{
					Subject: "Your verification code",
				},
			},
		},
	}

	deps := &Dependencies{
		MFARepo:      suite.mfaRepo,
		UserRepo:     suite.userRepo,
		SMSService:   suite.smsService,
		EmailService: suite.emailService,
		CacheService: suite.cacheService,
		Encryptor:    suite.encryptor,
	}

	suite.service = NewMFAService(suite.config, deps)
}

func (suite *MFAServiceTestSuite) TestSetupTOTP_Success() {
	userID := uuid.New().String()
	user := &UserData{
		ID:            userID,
		Email:         "test@example.com",
		AccountLocked: false,
	}

	req := &SetupTOTPRequest{
		UserID:      userID,
		AccountName: "test@example.com",
		Issuer:      "Test App",
	}

	// Mock user repository
	suite.userRepo.On("GetUserByID", suite.ctx, userID).Return(user, nil)

	// Mock MFA repository - no existing config
	suite.mfaRepo.On("GetUserMFAByMethod", suite.ctx, userID, MethodTOTP).Return(nil, errors.New(errors.ErrorTypeNotFound, "NOT_FOUND", "Not found"))

	// Mock encryption
	suite.encryptor.On("Encrypt", mock.AnythingOfType("[]uint8")).Return([]byte("encrypted_secret"), nil).Once()
	suite.encryptor.On("Encrypt", mock.AnythingOfType("[]uint8")).Return([]byte("encrypted_backup_codes"), nil).Once()

	// Mock MFA config creation
	createdConfig := &MFAConfigData{
		ID:                   uuid.New().String(),
		UserID:               userID,
		Method:               MethodTOTP,
		SecretEncrypted:      []byte("encrypted_secret"),
		BackupCodesEncrypted: []byte("encrypted_backup_codes"),
		Enabled:              false,
	}
	suite.mfaRepo.On("CreateMFAConfig", suite.ctx, mock.AnythingOfType("*mfa.MFAConfigData")).Return(createdConfig, nil)

	// Mock cache service for setup token
	suite.cacheService.On("Set", mock.AnythingOfType("*context.emptyCtx"), mock.AnythingOfType("string"), mock.AnythingOfType("*mfa.TOTPSetupToken"), int64(TOTPSetupTokenExpiration)).Return(nil)

	// Execute
	resp, err := suite.service.SetupTOTP(suite.ctx, req)

	// Assert
	suite.NoError(err)
	suite.NotNil(resp)
	suite.NotEmpty(resp.Secret)
	suite.NotEmpty(resp.QRCodeURL)
	suite.NotEmpty(resp.SetupToken)
	suite.Len(resp.BackupCodes, BackupCodesCount)
	suite.Contains(resp.Message, "TOTP setup initiated")

	// Verify mocks
	suite.userRepo.AssertExpectations(suite.T())
	suite.mfaRepo.AssertExpectations(suite.T())
	suite.encryptor.AssertExpectations(suite.T())
	suite.cacheService.AssertExpectations(suite.T())
}

func (suite *MFAServiceTestSuite) TestSetupTOTP_UserNotFound() {
	userID := uuid.New().String()
	req := &SetupTOTPRequest{
		UserID: userID,
	}

	// Mock user repository - user not found
	suite.userRepo.On("GetUserByID", suite.ctx, userID).Return(nil, errors.New(errors.ErrorTypeNotFound, "USER_NOT_FOUND", "User not found"))

	// Execute
	resp, err := suite.service.SetupTOTP(suite.ctx, req)

	// Assert
	suite.Error(err)
	suite.Nil(resp)
	suite.Equal(ErrUserNotFound, err)

	// Verify mocks
	suite.userRepo.AssertExpectations(suite.T())
}

func (suite *MFAServiceTestSuite) TestSetupTOTP_AlreadyExists() {
	userID := uuid.New().String()
	user := &UserData{
		ID:            userID,
		Email:         "test@example.com",
		AccountLocked: false,
	}

	req := &SetupTOTPRequest{
		UserID: userID,
	}

	existingConfig := &MFAConfigData{
		ID:      uuid.New().String(),
		UserID:  userID,
		Method:  MethodTOTP,
		Enabled: true,
	}

	// Mock user repository
	suite.userRepo.On("GetUserByID", suite.ctx, userID).Return(user, nil)

	// Mock MFA repository - existing config
	suite.mfaRepo.On("GetUserMFAByMethod", suite.ctx, userID, MethodTOTP).Return(existingConfig, nil)

	// Execute
	resp, err := suite.service.SetupTOTP(suite.ctx, req)

	// Assert
	suite.Error(err)
	suite.Nil(resp)
	suite.Contains(err.Error(), "already configured")

	// Verify mocks
	suite.userRepo.AssertExpectations(suite.T())
	suite.mfaRepo.AssertExpectations(suite.T())
}

func (suite *MFAServiceTestSuite) TestVerifyTOTP_SetupVerification_Success() {
	userID := uuid.New().String()
	configID := uuid.New().String()
	secret := "JBSWY3DPEHPK3PXP"
	setupToken := "setup_token_123"

	// Generate valid TOTP code
	code, err := totp.GenerateCode(secret, time.Now())
	suite.NoError(err)

	req := &VerifyTOTPRequest{
		SetupToken: setupToken,
		Code:       code,
	}

	// Mock setup token validation
	setupData := &TOTPSetupToken{
		UserID:    userID,
		ConfigID:  configID,
		Secret:    secret,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	setupDataJSON, _ := json.Marshal(setupData)
	suite.cacheService.On("Get", mock.AnythingOfType("*context.emptyCtx"), CacheKeyTOTPSetup+setupToken).Return(setupDataJSON, nil)

	// Mock MFA config retrieval
	config := &MFAConfigData{
		ID:      configID,
		UserID:  userID,
		Method:  MethodTOTP,
		Enabled: false,
	}
	suite.mfaRepo.On("GetMFAConfigByID", suite.ctx, configID).Return(config, nil)

	// Mock MFA enable
	suite.mfaRepo.On("EnableMFA", suite.ctx, configID).Return(nil)

	// Mock cache cleanup
	suite.cacheService.On("Delete", suite.ctx, CacheKeyTOTPSetup+setupToken).Return(nil)

	// Execute
	resp, err := suite.service.VerifyTOTP(suite.ctx, req)

	// Assert
	suite.NoError(err)
	suite.NotNil(resp)
	suite.True(resp.Valid)
	suite.True(resp.SetupComplete)
	suite.Equal(configID, resp.ConfigID)

	// Verify mocks
	suite.cacheService.AssertExpectations(suite.T())
	suite.mfaRepo.AssertExpectations(suite.T())
}

func (suite *MFAServiceTestSuite) TestVerifyTOTP_InvalidCode() {
	userID := uuid.New().String()
	configID := uuid.New().String()
	secret := "JBSWY3DPEHPK3PXP"

	req := &VerifyTOTPRequest{
		UserID: userID,
		Code:   "123456", // Invalid code
	}

	// Mock MFA config retrieval
	config := &MFAConfigData{
		ID:              configID,
		UserID:          userID,
		Method:          MethodTOTP,
		SecretEncrypted: []byte("encrypted_secret"),
		Enabled:         true,
	}
	suite.mfaRepo.On("GetUserMFAByMethod", suite.ctx, userID, MethodTOTP).Return(config, nil)

	// Mock decryption
	suite.encryptor.On("Decrypt", []byte("encrypted_secret")).Return([]byte(secret), nil)

	// Execute
	resp, err := suite.service.VerifyTOTP(suite.ctx, req)

	// Assert
	suite.Error(err)
	suite.Nil(resp)
	suite.Equal(ErrInvalidTOTPCode, err)

	// Verify mocks
	suite.mfaRepo.AssertExpectations(suite.T())
	suite.encryptor.AssertExpectations(suite.T())
}

func (suite *MFAServiceTestSuite) TestSetupSMS_Success() {
	userID := uuid.New().String()
	phoneNumber := "+1234567890"
	user := &UserData{
		ID:            userID,
		Email:         "test@example.com",
		AccountLocked: false,
	}

	req := &SetupSMSRequest{
		UserID:      userID,
		PhoneNumber: phoneNumber,
	}

	// Mock user repository
	suite.userRepo.On("GetUserByID", suite.ctx, userID).Return(user, nil)

	// Mock MFA repository - no existing config
	suite.mfaRepo.On("GetUserMFAByMethod", suite.ctx, userID, MethodSMS).Return(nil, errors.New(errors.ErrorTypeNotFound, "NOT_FOUND", "Not found"))

	// Mock encryption
	suite.encryptor.On("Encrypt", []byte(phoneNumber)).Return([]byte("encrypted_phone"), nil).Once()
	suite.encryptor.On("Encrypt", mock.AnythingOfType("[]uint8")).Return([]byte("encrypted_backup_codes"), nil).Once()

	// Mock MFA config creation
	createdConfig := &MFAConfigData{
		ID:                   uuid.New().String(),
		UserID:               userID,
		Method:               MethodSMS,
		SecretEncrypted:      []byte("encrypted_phone"),
		BackupCodesEncrypted: []byte("encrypted_backup_codes"),
		Enabled:              true,
	}
	suite.mfaRepo.On("CreateMFAConfig", suite.ctx, mock.AnythingOfType("*mfa.MFAConfigData")).Return(createdConfig, nil)

	// Execute
	resp, err := suite.service.SetupSMS(suite.ctx, req)

	// Assert
	suite.NoError(err)
	suite.NotNil(resp)
	suite.NotEmpty(resp.PhoneNumber)
	suite.Len(resp.BackupCodes, BackupCodesCount)
	suite.Contains(resp.Message, "SMS MFA setup completed")

	// Verify mocks
	suite.userRepo.AssertExpectations(suite.T())
	suite.mfaRepo.AssertExpectations(suite.T())
	suite.encryptor.AssertExpectations(suite.T())
}

func (suite *MFAServiceTestSuite) TestSendSMSCode_Success() {
	userID := uuid.New().String()
	configID := uuid.New().String()
	phoneNumber := "+1234567890"

	req := &SendSMSCodeRequest{
		UserID:   userID,
		ForLogin: true,
	}

	// Mock MFA config retrieval
	config := &MFAConfigData{
		ID:              configID,
		UserID:          userID,
		Method:          MethodSMS,
		SecretEncrypted: []byte("encrypted_phone"),
		Enabled:         true,
	}
	suite.mfaRepo.On("GetUserMFAByMethod", suite.ctx, userID, MethodSMS).Return(config, nil)

	// Mock decryption
	suite.encryptor.On("Decrypt", []byte("encrypted_phone")).Return([]byte(phoneNumber), nil)

	// Mock cache service
	suite.cacheService.On("Set", suite.ctx, mock.AnythingOfType("string"), mock.AnythingOfType("*mfa.VerificationCode"), int64(SMSCodeExpiration)).Return(nil)

	// Mock SMS service
	suite.smsService.On("SendSMS", suite.ctx, phoneNumber, mock.AnythingOfType("string")).Return(nil)

	// Execute
	resp, err := suite.service.SendSMSCode(suite.ctx, req)

	// Assert
	suite.NoError(err)
	suite.NotNil(resp)
	suite.True(resp.CodeSent)
	suite.Equal(int64(SMSCodeExpiration), resp.ExpiresIn)
	suite.NotEmpty(resp.PhoneNumber)

	// Verify mocks
	suite.mfaRepo.AssertExpectations(suite.T())
	suite.encryptor.AssertExpectations(suite.T())
	suite.cacheService.AssertExpectations(suite.T())
	suite.smsService.AssertExpectations(suite.T())
}

func (suite *MFAServiceTestSuite) TestValidateMFAForLogin_MFARequired() {
	userID := uuid.New().String()
	user := &UserData{
		ID:            userID,
		Email:         "test@example.com",
		AccountLocked: false,
	}

	req := &ValidateMFAForLoginRequest{
		UserID: userID,
	}

	// Mock user repository
	suite.userRepo.On("GetUserByID", suite.ctx, userID).Return(user, nil)

	// Mock enabled MFA methods
	enabledMethods := []string{MethodTOTP, MethodSMS}
	suite.mfaRepo.On("GetEnabledMFAMethods", suite.ctx, userID).Return(enabledMethods, nil)

	// Mock MFA configs
	configs := []*MFAConfigData{
		{
			ID:              uuid.New().String(),
			UserID:          userID,
			Method:          MethodTOTP,
			SecretEncrypted: []byte("encrypted_secret"),
			Enabled:         true,
		},
		{
			ID:              uuid.New().String(),
			UserID:          userID,
			Method:          MethodSMS,
			SecretEncrypted: []byte("encrypted_phone"),
			Enabled:         true,
		},
	}
	suite.mfaRepo.On("GetUserMFAConfigs", suite.ctx, userID).Return(configs, nil)

	// Mock decryption for display names
	suite.encryptor.On("Decrypt", []byte("encrypted_phone")).Return([]byte("+1234567890"), nil)

	// Execute
	resp, err := suite.service.ValidateMFAForLogin(suite.ctx, req)

	// Assert
	suite.NoError(err)
	suite.NotNil(resp)
	suite.True(resp.MFARequired)
	suite.Equal(enabledMethods, resp.Methods)
	suite.Len(resp.Configs, 2)
	suite.NotEmpty(resp.Challenge)

	// Verify mocks
	suite.userRepo.AssertExpectations(suite.T())
	suite.mfaRepo.AssertExpectations(suite.T())
}

func (suite *MFAServiceTestSuite) TestValidateMFAForLogin_MFANotRequired() {
	userID := uuid.New().String()
	user := &UserData{
		ID:            userID,
		Email:         "test@example.com",
		AccountLocked: false,
	}

	req := &ValidateMFAForLoginRequest{
		UserID: userID,
	}

	// Mock user repository
	suite.userRepo.On("GetUserByID", suite.ctx, userID).Return(user, nil)

	// Mock no enabled MFA methods
	suite.mfaRepo.On("GetEnabledMFAMethods", suite.ctx, userID).Return([]string{}, nil)

	// Execute
	resp, err := suite.service.ValidateMFAForLogin(suite.ctx, req)

	// Assert
	suite.NoError(err)
	suite.NotNil(resp)
	suite.False(resp.MFARequired)

	// Verify mocks
	suite.userRepo.AssertExpectations(suite.T())
	suite.mfaRepo.AssertExpectations(suite.T())
}

// Helper methods tests
func (suite *MFAServiceTestSuite) TestGenerateVerificationCode() {
	service := suite.service.(*mfaService)

	code, err := service.generateVerificationCode(6)
	suite.NoError(err)
	suite.Len(code, 6)

	// Verify all characters are digits
	for _, char := range code {
		suite.True(char >= '0' && char <= '9')
	}
}

func (suite *MFAServiceTestSuite) TestMaskPhoneNumber() {
	service := suite.service.(*mfaService)

	masked := service.maskPhoneNumber("+1234567890")
	suite.Equal("+12****890", masked)

	// Test short phone number
	masked = service.maskPhoneNumber("+12")
	suite.Equal("+12", masked)
}

func (suite *MFAServiceTestSuite) TestMaskEmail() {
	service := suite.service.(*mfaService)

	masked := service.maskEmail("test@example.com")
	suite.Equal("t**t@example.com", masked)

	// Test short username
	masked = service.maskEmail("ab@example.com")
	suite.Equal("ab@example.com", masked)
}

func (suite *MFAServiceTestSuite) TestIsValidPhoneNumber() {
	service := suite.service.(*mfaService)

	// Valid phone numbers
	suite.True(service.isValidPhoneNumber("+1234567890"))
	suite.True(service.isValidPhoneNumber("+12345678901234"))

	// Invalid phone numbers
	suite.False(service.isValidPhoneNumber("1234567890"))       // Missing +
	suite.False(service.isValidPhoneNumber("+0234567890"))      // Starts with 0
	suite.False(service.isValidPhoneNumber("+123456789012345")) // Too long
}

func (suite *MFAServiceTestSuite) TestIsValidEmail() {
	service := suite.service.(*mfaService)

	// Valid emails
	suite.True(service.isValidEmail("test@example.com"))
	suite.True(service.isValidEmail("user.name+tag@example.co.uk"))

	// Invalid emails
	suite.False(service.isValidEmail("invalid-email"))
	suite.False(service.isValidEmail("@example.com"))
	suite.False(service.isValidEmail("test@"))
}

// Run the test suite
func TestMFAServiceTestSuite(t *testing.T) {
	suite.Run(t, new(MFAServiceTestSuite))
}
