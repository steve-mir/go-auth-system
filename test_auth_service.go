package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/steve-mir/go-auth-system/internal/config"
	"github.com/steve-mir/go-auth-system/internal/errors"
	"github.com/steve-mir/go-auth-system/internal/security/crypto"
	"github.com/steve-mir/go-auth-system/internal/security/hash"
	"github.com/steve-mir/go-auth-system/internal/security/token"
	"github.com/steve-mir/go-auth-system/internal/service/auth"
)

// Mock implementations for testing
type mockUserRepo struct {
	users map[string]*auth.UserData
}

func (m *mockUserRepo) CreateUser(ctx context.Context, user *auth.CreateUserData) (*auth.UserData, error) {
	id := uuid.New().String()
	userData := &auth.UserData{
		ID:                 id,
		Email:              user.Email,
		Username:           user.Username,
		PasswordHash:       user.PasswordHash,
		HashAlgorithm:      user.HashAlgorithm,
		FirstNameEncrypted: user.FirstNameEncrypted,
		LastNameEncrypted:  user.LastNameEncrypted,
		PhoneEncrypted:     user.PhoneEncrypted,
		CreatedAt:          time.Now().Unix(),
		UpdatedAt:          time.Now().Unix(),
	}
	m.users[id] = userData
	return userData, nil
}

func (m *mockUserRepo) GetUserByEmail(ctx context.Context, email string) (*auth.UserData, error) {
	for _, user := range m.users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, errors.New(errors.ErrorTypeNotFound, "USER_NOT_FOUND", "User not found")
}

func (m *mockUserRepo) GetUserByUsername(ctx context.Context, username string) (*auth.UserData, error) {
	for _, user := range m.users {
		if user.Username == username {
			return user, nil
		}
	}
	return nil, errors.New(errors.ErrorTypeNotFound, "USER_NOT_FOUND", "User not found")
}

func (m *mockUserRepo) GetUserByID(ctx context.Context, userID string) (*auth.UserData, error) {
	if user, exists := m.users[userID]; exists {
		return user, nil
	}
	return nil, errors.New(errors.ErrorTypeNotFound, "USER_NOT_FOUND", "User not found")
}

func (m *mockUserRepo) UpdateUserLoginInfo(ctx context.Context, userID string, info *auth.LoginInfo) error {
	if user, exists := m.users[userID]; exists {
		user.FailedAttempts = info.FailedAttempts
		user.AccountLocked = info.AccountLocked
		user.LastLoginAt = info.LastLoginAt
		return nil
	}
	return errors.New(errors.ErrorTypeNotFound, "USER_NOT_FOUND", "User not found")
}

func (m *mockUserRepo) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	return []string{"user"}, nil
}

type mockSessionRepo struct {
	sessions map[string]*auth.SessionData
}

func (m *mockSessionRepo) CreateSession(ctx context.Context, session *auth.SessionData) error {
	m.sessions[session.ID] = session
	return nil
}

func (m *mockSessionRepo) GetSession(ctx context.Context, sessionID string) (*auth.SessionData, error) {
	if session, exists := m.sessions[sessionID]; exists {
		return session, nil
	}
	return nil, errors.New(errors.ErrorTypeNotFound, "SESSION_NOT_FOUND", "Session not found")
}

func (m *mockSessionRepo) UpdateSession(ctx context.Context, sessionID string, session *auth.SessionData) error {
	m.sessions[sessionID] = session
	return nil
}

func (m *mockSessionRepo) DeleteSession(ctx context.Context, sessionID string) error {
	delete(m.sessions, sessionID)
	return nil
}

func (m *mockSessionRepo) DeleteUserSessions(ctx context.Context, userID string) error {
	for id, session := range m.sessions {
		if session.UserID == userID {
			delete(m.sessions, id)
		}
	}
	return nil
}

func (m *mockSessionRepo) GetUserSessions(ctx context.Context, userID string) ([]*auth.SessionData, error) {
	var sessions []*auth.SessionData
	for _, session := range m.sessions {
		if session.UserID == userID {
			sessions = append(sessions, session)
		}
	}
	return sessions, nil
}

type mockBlacklistRepo struct {
	blacklist map[string]bool
}

func (m *mockBlacklistRepo) BlacklistToken(ctx context.Context, tokenHash string, expiresAt int64, reason string) error {
	m.blacklist[tokenHash] = true
	return nil
}

func (m *mockBlacklistRepo) IsTokenBlacklisted(ctx context.Context, tokenHash string) (bool, error) {
	return m.blacklist[tokenHash], nil
}

func (m *mockBlacklistRepo) BlacklistUserTokens(ctx context.Context, userID string, reason string) error {
	// For simplicity, just mark all as blacklisted
	return nil
}

func main() {
	fmt.Println("Testing Auth Service Implementation...")

	// Create test configuration
	cfg := &config.Config{
		Security: config.SecurityConfig{
			PasswordHash: config.PasswordHashConfig{
				Algorithm: "argon2",
			},
			Token: config.TokenConfig{
				Type:       "jwt",
				AccessTTL:  time.Hour,
				RefreshTTL: time.Hour * 24 * 7,
				SigningKey: "test-signing-key-32-bytes-long!!",
				Issuer:     "test-issuer",
				Audience:   "test-audience",
			},
		},
	}

	// Create mock repositories
	userRepo := &mockUserRepo{users: make(map[string]*auth.UserData)}
	sessionRepo := &mockSessionRepo{sessions: make(map[string]*auth.SessionData)}
	blacklistRepo := &mockBlacklistRepo{blacklist: make(map[string]bool)}

	// Create hash service
	hashFactory := hash.NewFactory(cfg.Security.PasswordHash)
	hashService, err := hashFactory.CreateHashService()
	if err != nil {
		log.Fatalf("Failed to create hash service: %v", err)
	}

	// Create token service
	tokenFactory := token.NewFactory(&cfg.Security.Token)
	tokenService, err := tokenFactory.CreateTokenService()
	if err != nil {
		log.Fatalf("Failed to create token service: %v", err)
	}

	// Create encryptor
	key := []byte("test-encryption-key-32-bytes-long")
	encryptor, err := crypto.NewAESGCMEncryptor(key)
	if err != nil {
		log.Fatalf("Failed to create encryptor: %v", err)
	}

	// Create auth service
	deps := &auth.Dependencies{
		UserRepo:      userRepo,
		SessionRepo:   sessionRepo,
		BlacklistRepo: blacklistRepo,
		TokenService:  tokenService,
		HashService:   hashService,
		Encryptor:     encryptor,
	}

	authService := auth.NewAuthService(cfg, deps)

	ctx := context.Background()

	// Test 1: User Registration
	fmt.Println("\n1. Testing User Registration...")
	registerReq := &auth.RegisterRequest{
		Email:     "test@example.com",
		Username:  "testuser",
		Password:  "password123",
		FirstName: "John",
		LastName:  "Doe",
		Phone:     "+1234567890",
	}

	registerResp, err := authService.Register(ctx, registerReq)
	if err != nil {
		log.Fatalf("Registration failed: %v", err)
	}
	fmt.Printf("✓ User registered successfully: %s\n", registerResp.Email)

	// Test 2: User Login
	fmt.Println("\n2. Testing User Login...")
	loginReq := &auth.LoginRequest{
		Email:     "test@example.com",
		Password:  "password123",
		IPAddress: "192.168.1.1",
		UserAgent: "test-agent",
	}

	loginResp, err := authService.Login(ctx, loginReq)
	if err != nil {
		log.Fatalf("Login failed: %v", err)
	}
	fmt.Printf("✓ User logged in successfully, got access token\n")

	// Test 3: Token Validation
	fmt.Println("\n3. Testing Token Validation...")
	validateReq := &auth.ValidateTokenRequest{
		Token: loginResp.AccessToken,
	}

	validateResp, err := authService.ValidateToken(ctx, validateReq)
	if err != nil {
		log.Fatalf("Token validation failed: %v", err)
	}
	if !validateResp.Valid {
		log.Fatalf("Token should be valid")
	}
	fmt.Printf("✓ Token validated successfully for user: %s\n", validateResp.Email)

	// Test 4: Token Refresh
	fmt.Println("\n4. Testing Token Refresh...")
	refreshReq := &auth.RefreshTokenRequest{
		RefreshToken: loginResp.RefreshToken,
		IPAddress:    "192.168.1.1",
		UserAgent:    "test-agent",
	}

	refreshResp, err := authService.RefreshToken(ctx, refreshReq)
	if err != nil {
		log.Fatalf("Token refresh failed: %v", err)
	}
	fmt.Printf("✓ Token refreshed successfully\n")

	// Test 5: User Logout
	fmt.Println("\n5. Testing User Logout...")
	logoutReq := &auth.LogoutRequest{
		AccessToken: refreshResp.AccessToken,
	}

	err = authService.Logout(ctx, logoutReq)
	if err != nil {
		log.Fatalf("Logout failed: %v", err)
	}
	fmt.Printf("✓ User logged out successfully\n")

	// Test 6: Invalid Login
	fmt.Println("\n6. Testing Invalid Login...")
	invalidLoginReq := &auth.LoginRequest{
		Email:    "test@example.com",
		Password: "wrongpassword",
	}

	_, err = authService.Login(ctx, invalidLoginReq)
	if err == nil {
		log.Fatalf("Invalid login should have failed")
	}
	fmt.Printf("✓ Invalid login correctly rejected\n")

	fmt.Println("\n🎉 All tests passed! Auth service is working correctly.")
}
