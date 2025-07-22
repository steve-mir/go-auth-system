package auth

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/steve-mir/go-auth-system/internal/config"
	"github.com/steve-mir/go-auth-system/internal/errors"
	"github.com/steve-mir/go-auth-system/internal/security/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Mock implementations
type mockUserRepository struct {
	mock.Mock
}

func (m *mockUserRepository) CreateUser(ctx context.Context, user *CreateUserData) (*UserData, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*UserData), args.Error(1)
}

func (m *mockUserRepository) GetUserByEmail(ctx context.Context, email string) (*UserData, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*UserData), args.Error(1)
}

func (m *mockUserRepository) GetUserByUsername(ctx context.Context, username string) (*UserData, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*UserData), args.Error(1)
}

func (m *mockUserRepository) GetUserByID(ctx context.Context, userID string) (*UserData, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*UserData), args.Error(1)
}

func (m *mockUserRepository) UpdateUserLoginInfo(ctx context.Context, userID string, info *LoginInfo) error {
	args := m.Called(ctx, userID, info)
	return args.Error(0)
}

func (m *mockUserRepository) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]string), args.Error(1)
}

type mockSessionRepository struct {
	mock.Mock
}

func (m *mockSessionRepository) CreateSession(ctx context.Context, session *SessionData) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}

func (m *mockSessionRepository) GetSession(ctx context.Context, sessionID string) (*SessionData, error) {
	args := m.Called(ctx, sessionID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*SessionData), args.Error(1)
}

func (m *mockSessionRepository) UpdateSession(ctx context.Context, sessionID string, session *SessionData) error {
	args := m.Called(ctx, sessionID, session)
	return args.Error(0)
}

func (m *mockSessionRepository) DeleteSession(ctx context.Context, sessionID string) error {
	args := m.Called(ctx, sessionID)
	return args.Error(0)
}

func (m *mockSessionRepository) DeleteUserSessions(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *mockSessionRepository) GetUserSessions(ctx context.Context, userID string) ([]*SessionData, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*SessionData), args.Error(1)
}

type mockTokenBlacklistRepository struct {
	mock.Mock
}

func (m *mockTokenBlacklistRepository) BlacklistToken(ctx context.Context, tokenHash string, expiresAt int64, reason string) error {
	args := m.Called(ctx, tokenHash, expiresAt, reason)
	return args.Error(0)
}

func (m *mockTokenBlacklistRepository) IsTokenBlacklisted(ctx context.Context, tokenHash string) (bool, error) {
	args := m.Called(ctx, tokenHash)
	return args.Bool(0), args.Error(1)
}

func (m *mockTokenBlacklistRepository) BlacklistUserTokens(ctx context.Context, userID string, reason string) error {
	args := m.Called(ctx, userID, reason)
	return args.Error(0)
}

type mockTokenService struct {
	mock.Mock
}

func (m *mockTokenService) GenerateTokens(ctx context.Context, userID string, claims token.TokenClaims) (*token.TokenPair, error) {
	args := m.Called(ctx, userID, claims)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*token.TokenPair), args.Error(1)
}

func (m *mockTokenService) ValidateToken(ctx context.Context, tokenStr string) (*token.TokenClaims, error) {
	args := m.Called(ctx, tokenStr)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*token.TokenClaims), args.Error(1)
}

func (m *mockTokenService) RefreshToken(ctx context.Context, refreshToken string) (*token.TokenPair, error) {
	args := m.Called(ctx, refreshToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*token.TokenPair), args.Error(1)
}

func (m *mockTokenService) RevokeToken(ctx context.Context, tokenStr string) error {
	args := m.Called(ctx, tokenStr)
	return args.Error(0)
}

func (m *mockTokenService) IsTokenRevoked(ctx context.Context, tokenID string) (bool, error) {
	args := m.Called(ctx, tokenID)
	return args.Bool(0), args.Error(1)
}

func (m *mockTokenService) GetTokenClaims(ctx context.Context, tokenStr string) (*token.TokenClaims, error) {
	args := m.Called(ctx, tokenStr)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*token.TokenClaims), args.Error(1)
}

func (m *mockTokenService) GetTokenType() string {
	args := m.Called()
	return args.String(0)
}

type mockHashService struct {
	mock.Mock
}

func (m *mockHashService) HashPassword(ctx context.Context, password string) (string, error) {
	args := m.Called(ctx, password)
	return args.String(0), args.Error(1)
}

func (m *mockHashService) VerifyPassword(ctx context.Context, password, hash string) error {
	args := m.Called(ctx, password, hash)
	return args.Error(0)
}

func (m *mockHashService) NeedsRehash(ctx context.Context, hash string) bool {
	args := m.Called(ctx, hash)
	return args.Bool(0)
}

type mockEncryptor struct {
	mock.Mock
}

func (m *mockEncryptor) Encrypt(data []byte) ([]byte, error) {
	args := m.Called(data)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *mockEncryptor) Decrypt(encryptedData []byte) ([]byte, error) {
	args := m.Called(encryptedData)
	return args.Get(0).([]byte), args.Error(1)
}

// Test setup helper
func setupAuthService(t *testing.T) (*authService, *mockUserRepository, *mockSessionRepository, *mockTokenBlacklistRepository, *mockTokenService, *mockHashService, *mockEncryptor) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			PasswordHash: config.PasswordHashConfig{
				Algorithm: "argon2",
			},
			Token: config.TokenConfig{
				AccessTTL:  time.Hour,
				RefreshTTL: time.Hour * 24 * 7,
				Issuer:     "test-issuer",
				Audience:   "test-audience",
			},
		},
	}

	userRepo := &mockUserRepository{}
	sessionRepo := &mockSessionRepository{}
	blacklistRepo := &mockTokenBlacklistRepository{}
	tokenService := &mockTokenService{}
	hashService := &mockHashService{}
	encryptor := &mockEncryptor{}

	deps := &Dependencies{
		UserRepo:      userRepo,
		SessionRepo:   sessionRepo,
		BlacklistRepo: blacklistRepo,
		TokenService:  tokenService,
		HashService:   hashService,
		Encryptor:     encryptor,
	}

	service := NewAuthService(cfg, deps).(*authService)

	return service, userRepo, sessionRepo, blacklistRepo, tokenService, hashService, encryptor
}

func TestAuthService_Register(t *testing.T) {
	t.Run("successful registration", func(t *testing.T) {
		service, userRepo, _, _, _, hashService, encryptor := setupAuthService(t)
		ctx := context.Background()

		req := &RegisterRequest{
			Email:     "test@example.com",
			Username:  "testuser",
			Password:  "password123",
			FirstName: "John",
			LastName:  "Doe",
			Phone:     "+1234567890",
		}

		// Mock expectations
		userRepo.On("GetUserByEmail", ctx, req.Email).Return(nil, errors.New(errors.ErrorTypeNotFound, "NOT_FOUND", "User not found"))
		userRepo.On("GetUserByUsername", ctx, req.Username).Return(nil, errors.New(errors.ErrorTypeNotFound, "NOT_FOUND", "User not found"))
		hashService.On("HashPassword", ctx, req.Password).Return("hashed_password", nil)
		encryptor.On("Encrypt", []byte(req.FirstName)).Return([]byte("encrypted_first_name"), nil)
		encryptor.On("Encrypt", []byte(req.LastName)).Return([]byte("encrypted_last_name"), nil)
		encryptor.On("Encrypt", []byte(req.Phone)).Return([]byte("encrypted_phone"), nil)

		userID := uuid.New().String()
		createdUser := &UserData{
			ID:        userID,
			Email:     req.Email,
			Username:  req.Username,
			CreatedAt: time.Now().Unix(),
		}
		userRepo.On("CreateUser", ctx, mock.AnythingOfType("*auth.CreateUserData")).Return(createdUser, nil)

		// Execute
		resp, err := service.Register(ctx, req)

		// Assert
		require.NoError(t, err)
		assert.Equal(t, req.Email, resp.Email)
		assert.Equal(t, req.Username, resp.Username)
		assert.Equal(t, "User registered successfully", resp.Message)
		userRepo.AssertExpectations(t)
		hashService.AssertExpectations(t)
		encryptor.AssertExpectations(t)
	})

	t.Run("user already exists by email", func(t *testing.T) {
		service, userRepo, _, _, _, _, _ := setupAuthService(t)
		ctx := context.Background()

		req := &RegisterRequest{
			Email:    "test@example.com",
			Password: "password123",
		}

		existingUser := &UserData{
			ID:    uuid.New().String(),
			Email: req.Email,
		}
		userRepo.On("GetUserByEmail", ctx, req.Email).Return(existingUser, nil)

		// Execute
		resp, err := service.Register(ctx, req)

		// Assert
		assert.Nil(t, resp)
		assert.Error(t, err)
		assert.True(t, errors.IsType(err, errors.ErrorTypeConflict))
		userRepo.AssertExpectations(t)
	})

	t.Run("invalid email format", func(t *testing.T) {
		service, _, _, _, _, _, _ := setupAuthService(t)
		ctx := context.Background()

		req := &RegisterRequest{
			Email:    "invalid-email",
			Password: "password123",
		}

		// Execute
		resp, err := service.Register(ctx, req)

		// Assert
		assert.Nil(t, resp)
		assert.Error(t, err)
		assert.True(t, errors.IsType(err, errors.ErrorTypeValidation))
	})

	t.Run("password too weak", func(t *testing.T) {
		service, _, _, _, _, _, _ := setupAuthService(t)
		ctx := context.Background()

		req := &RegisterRequest{
			Email:    "test@example.com",
			Password: "123",
		}

		// Execute
		resp, err := service.Register(ctx, req)

		// Assert
		assert.Nil(t, resp)
		assert.Error(t, err)
		assert.True(t, errors.IsType(err, errors.ErrorTypeValidation))
	})
}

func TestAuthService_Login(t *testing.T) {
	t.Run("successful login with email", func(t *testing.T) {
		service, userRepo, sessionRepo, _, tokenService, hashService, _ := setupAuthService(t)
		ctx := context.Background()

		req := &LoginRequest{
			Email:     "test@example.com",
			Password:  "password123",
			IPAddress: "192.168.1.1",
			UserAgent: "test-agent",
		}

		userID := uuid.New().String()
		user := &UserData{
			ID:            userID,
			Email:         req.Email,
			Username:      "testuser",
			PasswordHash:  "hashed_password",
			AccountLocked: false,
		}

		tokenPair := &token.TokenPair{
			AccessToken:  "access_token",
			RefreshToken: "refresh_token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			ExpiresAt:    time.Now().Add(time.Hour),
		}

		// Mock expectations
		userRepo.On("GetUserByEmail", ctx, req.Email).Return(user, nil)
		hashService.On("VerifyPassword", ctx, req.Password, user.PasswordHash).Return(nil)
		userRepo.On("UpdateUserLoginInfo", ctx, userID, mock.AnythingOfType("*auth.LoginInfo")).Return(nil)
		userRepo.On("GetUserRoles", ctx, userID).Return([]string{"user"}, nil)
		tokenService.On("GenerateTokens", ctx, userID, mock.AnythingOfType("token.TokenClaims")).Return(tokenPair, nil)
		sessionRepo.On("CreateSession", ctx, mock.AnythingOfType("*auth.SessionData")).Return(nil)

		// Execute
		resp, err := service.Login(ctx, req)

		// Assert
		require.NoError(t, err)
		assert.Equal(t, user.Email, resp.Email)
		assert.Equal(t, user.Username, resp.Username)
		assert.Equal(t, tokenPair.AccessToken, resp.AccessToken)
		assert.Equal(t, tokenPair.RefreshToken, resp.RefreshToken)
		userRepo.AssertExpectations(t)
		hashService.AssertExpectations(t)
		tokenService.AssertExpectations(t)
		sessionRepo.AssertExpectations(t)
	})

	t.Run("successful login with username", func(t *testing.T) {
		service, userRepo, sessionRepo, _, tokenService, hashService, _ := setupAuthService(t)
		ctx := context.Background()

		req := &LoginRequest{
			Username:  "testuser",
			Password:  "password123",
			IPAddress: "192.168.1.1",
			UserAgent: "test-agent",
		}

		userID := uuid.New().String()
		user := &UserData{
			ID:            userID,
			Email:         "test@example.com",
			Username:      req.Username,
			PasswordHash:  "hashed_password",
			AccountLocked: false,
		}

		tokenPair := &token.TokenPair{
			AccessToken:  "access_token",
			RefreshToken: "refresh_token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			ExpiresAt:    time.Now().Add(time.Hour),
		}

		// Mock expectations
		userRepo.On("GetUserByUsername", ctx, req.Username).Return(user, nil)
		hashService.On("VerifyPassword", ctx, req.Password, user.PasswordHash).Return(nil)
		userRepo.On("UpdateUserLoginInfo", ctx, userID, mock.AnythingOfType("*auth.LoginInfo")).Return(nil)
		userRepo.On("GetUserRoles", ctx, userID).Return([]string{"user"}, nil)
		tokenService.On("GenerateTokens", ctx, userID, mock.AnythingOfType("token.TokenClaims")).Return(tokenPair, nil)
		sessionRepo.On("CreateSession", ctx, mock.AnythingOfType("*auth.SessionData")).Return(nil)

		// Execute
		resp, err := service.Login(ctx, req)

		// Assert
		require.NoError(t, err)
		assert.Equal(t, user.Email, resp.Email)
		assert.Equal(t, user.Username, resp.Username)
		userRepo.AssertExpectations(t)
		hashService.AssertExpectations(t)
		tokenService.AssertExpectations(t)
		sessionRepo.AssertExpectations(t)
	})

	t.Run("invalid credentials", func(t *testing.T) {
		service, userRepo, _, _, _, hashService, _ := setupAuthService(t)
		ctx := context.Background()

		req := &LoginRequest{
			Email:    "test@example.com",
			Password: "wrong_password",
		}

		user := &UserData{
			ID:            uuid.New().String(),
			Email:         req.Email,
			PasswordHash:  "hashed_password",
			AccountLocked: false,
		}

		// Mock expectations
		userRepo.On("GetUserByEmail", ctx, req.Email).Return(user, nil)
		hashService.On("VerifyPassword", ctx, req.Password, user.PasswordHash).Return(errors.New(errors.ErrorTypeAuthentication, "INVALID_PASSWORD", "Invalid password"))
		userRepo.On("UpdateUserLoginInfo", ctx, user.ID, mock.AnythingOfType("*auth.LoginInfo")).Return(nil)

		// Execute
		resp, err := service.Login(ctx, req)

		// Assert
		assert.Nil(t, resp)
		assert.Error(t, err)
		assert.True(t, errors.IsType(err, errors.ErrorTypeAuthentication))
		userRepo.AssertExpectations(t)
		hashService.AssertExpectations(t)
	})

	t.Run("account locked", func(t *testing.T) {
		service, userRepo, _, _, _, _, _ := setupAuthService(t)
		ctx := context.Background()

		req := &LoginRequest{
			Email:    "test@example.com",
			Password: "password123",
		}

		user := &UserData{
			ID:            uuid.New().String(),
			Email:         req.Email,
			PasswordHash:  "hashed_password",
			AccountLocked: true,
		}

		// Mock expectations
		userRepo.On("GetUserByEmail", ctx, req.Email).Return(user, nil)

		// Execute
		resp, err := service.Login(ctx, req)

		// Assert
		assert.Nil(t, resp)
		assert.Error(t, err)
		assert.True(t, errors.IsType(err, errors.ErrorTypeAuthentication))
		userRepo.AssertExpectations(t)
	})

	t.Run("user not found", func(t *testing.T) {
		service, userRepo, _, _, _, _, _ := setupAuthService(t)
		ctx := context.Background()

		req := &LoginRequest{
			Email:    "nonexistent@example.com",
			Password: "password123",
		}

		// Mock expectations
		userRepo.On("GetUserByEmail", ctx, req.Email).Return(nil, errors.New(errors.ErrorTypeNotFound, "NOT_FOUND", "User not found"))

		// Execute
		resp, err := service.Login(ctx, req)

		// Assert
		assert.Nil(t, resp)
		assert.Error(t, err)
		assert.True(t, errors.IsType(err, errors.ErrorTypeAuthentication))
		userRepo.AssertExpectations(t)
	})

	t.Run("missing email and username", func(t *testing.T) {
		service, _, _, _, _, _, _ := setupAuthService(t)
		ctx := context.Background()

		req := &LoginRequest{
			Password: "password123",
		}

		// Execute
		resp, err := service.Login(ctx, req)

		// Assert
		assert.Nil(t, resp)
		assert.Error(t, err)
		assert.True(t, errors.IsType(err, errors.ErrorTypeValidation))
	})
}

func TestAuthService_Logout(t *testing.T) {
	t.Run("successful logout with access token", func(t *testing.T) {
		service, _, sessionRepo, _, tokenService, _, _ := setupAuthService(t)
		ctx := context.Background()

		req := &LogoutRequest{
			AccessToken: "access_token",
		}

		claims := &token.TokenClaims{
			UserID: uuid.New().String(),
			JTI:    uuid.New().String(),
		}

		// Mock expectations
		tokenService.On("GetTokenClaims", ctx, req.AccessToken).Return(claims, nil)
		tokenService.On("RevokeToken", ctx, req.AccessToken).Return(nil)
		sessionRepo.On("GetUserSessions", ctx, claims.UserID).Return([]*SessionData{}, nil)

		// Execute
		err := service.Logout(ctx, req)

		// Assert
		require.NoError(t, err)
		tokenService.AssertExpectations(t)
		sessionRepo.AssertExpectations(t)
	})

	t.Run("successful logout all sessions", func(t *testing.T) {
		service, _, sessionRepo, blacklistRepo, tokenService, _, _ := setupAuthService(t)
		ctx := context.Background()

		req := &LogoutRequest{
			AccessToken: "access_token",
			AllSessions: true,
		}

		claims := &token.TokenClaims{
			UserID: uuid.New().String(),
			JTI:    uuid.New().String(),
		}

		// Mock expectations
		tokenService.On("GetTokenClaims", ctx, req.AccessToken).Return(claims, nil)
		tokenService.On("RevokeToken", ctx, req.AccessToken).Return(nil)
		blacklistRepo.On("BlacklistUserTokens", ctx, claims.UserID, "user logout all sessions").Return(nil)
		sessionRepo.On("DeleteUserSessions", ctx, claims.UserID).Return(nil)

		// Execute
		err := service.Logout(ctx, req)

		// Assert
		require.NoError(t, err)
		tokenService.AssertExpectations(t)
		blacklistRepo.AssertExpectations(t)
		sessionRepo.AssertExpectations(t)
	})

	t.Run("missing token", func(t *testing.T) {
		service, _, _, _, _, _, _ := setupAuthService(t)
		ctx := context.Background()

		req := &LogoutRequest{}

		// Execute
		err := service.Logout(ctx, req)

		// Assert
		assert.Error(t, err)
		assert.True(t, errors.IsType(err, errors.ErrorTypeValidation))
	})

	t.Run("invalid token", func(t *testing.T) {
		service, _, _, _, tokenService, _, _ := setupAuthService(t)
		ctx := context.Background()

		req := &LogoutRequest{
			AccessToken: "invalid_token",
		}

		// Mock expectations
		tokenService.On("GetTokenClaims", ctx, req.AccessToken).Return(nil, errors.New(errors.ErrorTypeAuthentication, "INVALID_TOKEN", "Invalid token"))

		// Execute
		err := service.Logout(ctx, req)

		// Assert
		assert.Error(t, err)
		assert.True(t, errors.IsType(err, errors.ErrorTypeAuthentication))
		tokenService.AssertExpectations(t)
	})
}

func TestAuthService_RefreshToken(t *testing.T) {
	t.Run("successful token refresh", func(t *testing.T) {
		service, userRepo, sessionRepo, _, tokenService, _, _ := setupAuthService(t)
		ctx := context.Background()

		req := &RefreshTokenRequest{
			RefreshToken: "refresh_token",
			IPAddress:    "192.168.1.1",
			UserAgent:    "test-agent",
		}

		userID := uuid.New().String()
		claims := &token.TokenClaims{
			UserID:    userID,
			TokenType: token.TokenTypeRefresh,
			JTI:       uuid.New().String(),
		}

		user := &UserData{
			ID:            userID,
			Email:         "test@example.com",
			Username:      "testuser",
			AccountLocked: false,
		}

		newTokenPair := &token.TokenPair{
			AccessToken:  "new_access_token",
			RefreshToken: "new_refresh_token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			ExpiresAt:    time.Now().Add(time.Hour),
		}

		// Mock expectations
		tokenService.On("ValidateToken", ctx, req.RefreshToken).Return(claims, nil)
		tokenService.On("IsTokenRevoked", ctx, claims.JTI).Return(false, nil)
		userRepo.On("GetUserByID", ctx, userID).Return(user, nil)
		userRepo.On("GetUserRoles", ctx, userID).Return([]string{"user"}, nil)
		tokenService.On("GenerateTokens", ctx, userID, mock.AnythingOfType("token.TokenClaims")).Return(newTokenPair, nil)
		tokenService.On("RevokeToken", ctx, req.RefreshToken).Return(nil)
		sessionRepo.On("GetUserSessions", ctx, userID).Return([]*SessionData{}, nil)

		// Execute
		resp, err := service.RefreshToken(ctx, req)

		// Assert
		require.NoError(t, err)
		assert.Equal(t, newTokenPair.AccessToken, resp.AccessToken)
		assert.Equal(t, newTokenPair.RefreshToken, resp.RefreshToken)
		tokenService.AssertExpectations(t)
		userRepo.AssertExpectations(t)
		sessionRepo.AssertExpectations(t)
	})

	t.Run("invalid refresh token", func(t *testing.T) {
		service, _, _, _, tokenService, _, _ := setupAuthService(t)
		ctx := context.Background()

		req := &RefreshTokenRequest{
			RefreshToken: "invalid_token",
		}

		// Mock expectations
		tokenService.On("ValidateToken", ctx, req.RefreshToken).Return(nil, errors.New(errors.ErrorTypeAuthentication, "INVALID_TOKEN", "Invalid token"))

		// Execute
		resp, err := service.RefreshToken(ctx, req)

		// Assert
		assert.Nil(t, resp)
		assert.Error(t, err)
		assert.True(t, errors.IsType(err, errors.ErrorTypeAuthentication))
		tokenService.AssertExpectations(t)
	})

	t.Run("not a refresh token", func(t *testing.T) {
		service, _, _, _, tokenService, _, _ := setupAuthService(t)
		ctx := context.Background()

		req := &RefreshTokenRequest{
			RefreshToken: "access_token",
		}

		claims := &token.TokenClaims{
			UserID:    uuid.New().String(),
			TokenType: token.TokenTypeAccess, // Wrong token type
			JTI:       uuid.New().String(),
		}

		// Mock expectations
		tokenService.On("ValidateToken", ctx, req.RefreshToken).Return(claims, nil)

		// Execute
		resp, err := service.RefreshToken(ctx, req)

		// Assert
		assert.Nil(t, resp)
		assert.Error(t, err)
		assert.True(t, errors.IsType(err, errors.ErrorTypeAuthentication))
		tokenService.AssertExpectations(t)
	})

	t.Run("revoked token", func(t *testing.T) {
		service, _, _, _, tokenService, _, _ := setupAuthService(t)
		ctx := context.Background()

		req := &RefreshTokenRequest{
			RefreshToken: "revoked_token",
		}

		claims := &token.TokenClaims{
			UserID:    uuid.New().String(),
			TokenType: token.TokenTypeRefresh,
			JTI:       uuid.New().String(),
		}

		// Mock expectations
		tokenService.On("ValidateToken", ctx, req.RefreshToken).Return(claims, nil)
		tokenService.On("IsTokenRevoked", ctx, claims.JTI).Return(true, nil)

		// Execute
		resp, err := service.RefreshToken(ctx, req)

		// Assert
		assert.Nil(t, resp)
		assert.Error(t, err)
		assert.True(t, errors.IsType(err, errors.ErrorTypeAuthentication))
		tokenService.AssertExpectations(t)
	})

	t.Run("user not found", func(t *testing.T) {
		service, userRepo, _, _, tokenService, _, _ := setupAuthService(t)
		ctx := context.Background()

		req := &RefreshTokenRequest{
			RefreshToken: "refresh_token",
		}

		userID := uuid.New().String()
		claims := &token.TokenClaims{
			UserID:    userID,
			TokenType: token.TokenTypeRefresh,
			JTI:       uuid.New().String(),
		}

		// Mock expectations
		tokenService.On("ValidateToken", ctx, req.RefreshToken).Return(claims, nil)
		tokenService.On("IsTokenRevoked", ctx, claims.JTI).Return(false, nil)
		userRepo.On("GetUserByID", ctx, userID).Return(nil, errors.New(errors.ErrorTypeNotFound, "NOT_FOUND", "User not found"))

		// Execute
		resp, err := service.RefreshToken(ctx, req)

		// Assert
		assert.Nil(t, resp)
		assert.Error(t, err)
		assert.True(t, errors.IsType(err, errors.ErrorTypeNotFound))
		tokenService.AssertExpectations(t)
		userRepo.AssertExpectations(t)
	})

	t.Run("account locked", func(t *testing.T) {
		service, userRepo, _, _, tokenService, _, _ := setupAuthService(t)
		ctx := context.Background()

		req := &RefreshTokenRequest{
			RefreshToken: "refresh_token",
		}

		userID := uuid.New().String()
		claims := &token.TokenClaims{
			UserID:    userID,
			TokenType: token.TokenTypeRefresh,
			JTI:       uuid.New().String(),
		}

		user := &UserData{
			ID:            userID,
			Email:         "test@example.com",
			AccountLocked: true,
		}

		// Mock expectations
		tokenService.On("ValidateToken", ctx, req.RefreshToken).Return(claims, nil)
		tokenService.On("IsTokenRevoked", ctx, claims.JTI).Return(false, nil)
		userRepo.On("GetUserByID", ctx, userID).Return(user, nil)

		// Execute
		resp, err := service.RefreshToken(ctx, req)

		// Assert
		assert.Nil(t, resp)
		assert.Error(t, err)
		assert.True(t, errors.IsType(err, errors.ErrorTypeAuthentication))
		tokenService.AssertExpectations(t)
		userRepo.AssertExpectations(t)
	})
}

func TestAuthService_ValidateToken(t *testing.T) {
	t.Run("valid token", func(t *testing.T) {
		service, userRepo, _, _, tokenService, _, _ := setupAuthService(t)
		ctx := context.Background()

		req := &ValidateTokenRequest{
			Token: "valid_token",
		}

		userID := uuid.New().String()
		claims := &token.TokenClaims{
			UserID:    userID,
			Email:     "test@example.com",
			Username:  "testuser",
			Roles:     []string{"user"},
			TokenType: token.TokenTypeAccess,
			ExpiresAt: time.Now().Add(time.Hour),
			JTI:       uuid.New().String(),
		}

		user := &UserData{
			ID:            userID,
			Email:         claims.Email,
			AccountLocked: false,
		}

		// Mock expectations
		tokenService.On("ValidateToken", ctx, req.Token).Return(claims, nil)
		tokenService.On("IsTokenRevoked", ctx, claims.JTI).Return(false, nil)
		userRepo.On("GetUserByID", ctx, userID).Return(user, nil)

		// Execute
		resp, err := service.ValidateToken(ctx, req)

		// Assert
		require.NoError(t, err)
		assert.True(t, resp.Valid)
		assert.Equal(t, claims.UserID, resp.UserID)
		assert.Equal(t, claims.Email, resp.Email)
		assert.Equal(t, claims.Username, resp.Username)
		assert.Equal(t, claims.Roles, resp.Roles)
		tokenService.AssertExpectations(t)
		userRepo.AssertExpectations(t)
	})

	t.Run("invalid token", func(t *testing.T) {
		service, _, _, _, tokenService, _, _ := setupAuthService(t)
		ctx := context.Background()

		req := &ValidateTokenRequest{
			Token: "invalid_token",
		}

		// Mock expectations
		tokenService.On("ValidateToken", ctx, req.Token).Return(nil, errors.New(errors.ErrorTypeAuthentication, "INVALID_TOKEN", "Invalid token"))

		// Execute
		resp, err := service.ValidateToken(ctx, req)

		// Assert
		require.NoError(t, err)
		assert.False(t, resp.Valid)
		tokenService.AssertExpectations(t)
	})

	t.Run("revoked token", func(t *testing.T) {
		service, _, _, _, tokenService, _, _ := setupAuthService(t)
		ctx := context.Background()

		req := &ValidateTokenRequest{
			Token: "revoked_token",
		}

		claims := &token.TokenClaims{
			UserID: uuid.New().String(),
			JTI:    uuid.New().String(),
		}

		// Mock expectations
		tokenService.On("ValidateToken", ctx, req.Token).Return(claims, nil)
		tokenService.On("IsTokenRevoked", ctx, claims.JTI).Return(true, nil)

		// Execute
		resp, err := service.ValidateToken(ctx, req)

		// Assert
		require.NoError(t, err)
		assert.False(t, resp.Valid)
		tokenService.AssertExpectations(t)
	})

	t.Run("user not found", func(t *testing.T) {
		service, userRepo, _, _, tokenService, _, _ := setupAuthService(t)
		ctx := context.Background()

		req := &ValidateTokenRequest{
			Token: "valid_token",
		}

		userID := uuid.New().String()
		claims := &token.TokenClaims{
			UserID: userID,
			JTI:    uuid.New().String(),
		}

		// Mock expectations
		tokenService.On("ValidateToken", ctx, req.Token).Return(claims, nil)
		tokenService.On("IsTokenRevoked", ctx, claims.JTI).Return(false, nil)
		userRepo.On("GetUserByID", ctx, userID).Return(nil, errors.New(errors.ErrorTypeNotFound, "NOT_FOUND", "User not found"))

		// Execute
		resp, err := service.ValidateToken(ctx, req)

		// Assert
		require.NoError(t, err)
		assert.False(t, resp.Valid)
		tokenService.AssertExpectations(t)
		userRepo.AssertExpectations(t)
	})

	t.Run("account locked", func(t *testing.T) {
		service, userRepo, _, _, tokenService, _, _ := setupAuthService(t)
		ctx := context.Background()

		req := &ValidateTokenRequest{
			Token: "valid_token",
		}

		userID := uuid.New().String()
		claims := &token.TokenClaims{
			UserID: userID,
			JTI:    uuid.New().String(),
		}

		user := &UserData{
			ID:            userID,
			AccountLocked: true,
		}

		// Mock expectations
		tokenService.On("ValidateToken", ctx, req.Token).Return(claims, nil)
		tokenService.On("IsTokenRevoked", ctx, claims.JTI).Return(false, nil)
		userRepo.On("GetUserByID", ctx, userID).Return(user, nil)

		// Execute
		resp, err := service.ValidateToken(ctx, req)

		// Assert
		require.NoError(t, err)
		assert.False(t, resp.Valid)
		tokenService.AssertExpectations(t)
		userRepo.AssertExpectations(t)
	})
}
