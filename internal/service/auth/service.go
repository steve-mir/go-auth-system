package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/steve-mir/go-auth-system/internal/config"
	"github.com/steve-mir/go-auth-system/internal/errors"
	"github.com/steve-mir/go-auth-system/internal/interfaces"
	"github.com/steve-mir/go-auth-system/internal/security/token"
)

// authService implements the AuthService interface
type authService struct {
	config        *config.Config
	userRepo      UserRepository
	sessionRepo   SessionRepository
	blacklistRepo TokenBlacklistRepository
	tokenService  token.TokenService
	hashService   HashService
	encryptor     Encryptor
}

// NewAuthService creates a new authentication service
func NewAuthService(cfg *config.Config, deps *Dependencies) interfaces.AuthService {
	return &authService{
		config:        cfg,
		userRepo:      deps.UserRepo,
		sessionRepo:   deps.SessionRepo,
		blacklistRepo: deps.BlacklistRepo,
		tokenService:  deps.TokenService,
		hashService:   deps.HashService,
		encryptor:     deps.Encryptor,
	}
}

// Register creates a new user account with encrypted sensitive data
func (s *authService) Register(ctx context.Context, req *interfaces.RegisterRequest) (*interfaces.RegisterResponse, error) {
	// Validate request
	if err := s.validateRegisterRequest(req); err != nil {
		return nil, err
	}

	// Check if user already exists
	if existingUser, _ := s.userRepo.GetUserByEmail(ctx, req.Email); existingUser != nil {
		return nil, ErrUserAlreadyExists.WithDetails(map[string]string{"field": "email"})
	}

	if req.Username != "" {
		if existingUser, _ := s.userRepo.GetUserByUsername(ctx, req.Username); existingUser != nil {
			return nil, ErrUserAlreadyExists.WithDetails(map[string]string{"field": "username"})
		}
	}

	// Hash password
	passwordHash, err := s.hashService.HashPassword(ctx, req.Password)
	if err != nil {
		return nil, ErrHashingFailed.WithCause(err)
	}

	// Encrypt sensitive data
	var firstNameEncrypted, lastNameEncrypted, phoneEncrypted []byte

	if req.FirstName != "" {
		firstNameEncrypted, err = s.encryptor.Encrypt([]byte(req.FirstName))
		if err != nil {
			return nil, errors.Wrap(err, errors.ErrorTypeInternal, "ENCRYPTION_FAILED", "Failed to encrypt first name")
		}
	}

	if req.LastName != "" {
		lastNameEncrypted, err = s.encryptor.Encrypt([]byte(req.LastName))
		if err != nil {
			return nil, errors.Wrap(err, errors.ErrorTypeInternal, "ENCRYPTION_FAILED", "Failed to encrypt last name")
		}
	}

	if req.Phone != "" {
		phoneEncrypted, err = s.encryptor.Encrypt([]byte(req.Phone))
		if err != nil {
			return nil, errors.Wrap(err, errors.ErrorTypeInternal, "ENCRYPTION_FAILED", "Failed to encrypt phone")
		}
	}

	// Create user data
	userData := &interfaces.CreateUserData{
		Email:              req.Email,
		Username:           req.Username,
		PasswordHash:       passwordHash,
		HashAlgorithm:      s.config.Security.PasswordHash.Algorithm,
		FirstNameEncrypted: firstNameEncrypted,
		LastNameEncrypted:  lastNameEncrypted,
		PhoneEncrypted:     phoneEncrypted,
	}

	// Create user in database
	createdUser, err := s.userRepo.CreateUser(ctx, userData)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "USER_CREATION_FAILED", "Failed to create user")
	}

	return &interfaces.RegisterResponse{
		UserID:    uuid.MustParse(createdUser.ID),
		Email:     createdUser.Email,
		Username:  createdUser.Username,
		CreatedAt: time.Unix(createdUser.CreatedAt, 0),
		Message:   "User registered successfully",
	}, nil
}

// Login authenticates a user and returns tokens
func (s *authService) Login(ctx context.Context, req *interfaces.LoginRequest) (*interfaces.LoginResponse, error) {
	// Validate request
	if err := s.validateLoginRequest(req); err != nil {
		return nil, err
	}

	// Get user by email or username
	var user *interfaces.UserData
	var err error

	if req.Email != "" {
		user, err = s.userRepo.GetUserByEmail(ctx, req.Email)
	} else {
		user, err = s.userRepo.GetUserByUsername(ctx, req.Username)
	}

	if err != nil || user == nil {
		return nil, ErrInvalidCredentials
	}

	// Check if account is locked
	if user.AccountLocked {
		return nil, ErrAccountLocked
	}

	// Verify password
	if err := s.hashService.VerifyPassword(ctx, req.Password, user.PasswordHash); err != nil {
		// Increment failed login attempts
		s.handleFailedLogin(ctx, user)
		return nil, ErrInvalidCredentials
	}

	// Reset failed login attempts on successful login
	now := time.Now().Unix()
	loginInfo := &interfaces.LoginInfo{
		FailedAttempts: 0,
		AccountLocked:  false,
		LastLoginAt:    &now,
	}
	s.userRepo.UpdateUserLoginInfo(ctx, user.ID, loginInfo)

	// Get user roles
	roles, err := s.userRepo.GetUserRoles(ctx, user.ID)
	if err != nil {
		roles = []string{} // Default to empty roles if error
	}

	// Generate tokens
	tokenClaims := token.TokenClaims{
		UserID:    user.ID,
		Email:     user.Email,
		Username:  user.Username,
		Roles:     roles,
		TokenType: token.TokenTypeAccess,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(s.config.Security.Token.AccessTTL),
		Issuer:    s.config.Security.Token.Issuer,
		Audience:  s.config.Security.Token.Audience,
		Subject:   user.ID,
		JTI:       uuid.New().String(),
	}

	tokenPair, err := s.tokenService.GenerateTokens(ctx, user.ID, tokenClaims)
	if err != nil {
		return nil, ErrTokenGenerationFailed.WithCause(err)
	}

	// Create session
	sessionData := &interfaces.SessionData{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		TokenHash: s.hashToken(tokenPair.AccessToken),
		TokenType: "access",
		Roles:     roles,
		ExpiresAt: tokenPair.ExpiresAt.Unix(),
		IPAddress: req.IPAddress,
		UserAgent: req.UserAgent,
		CreatedAt: time.Now().Unix(),
		LastUsed:  time.Now().Unix(),
	}

	if err := s.sessionRepo.CreateSession(ctx, sessionData); err != nil {
		// Log error but don't fail login
		// In production, you might want to handle this differently
	}

	return &interfaces.LoginResponse{
		UserID:       uuid.MustParse(user.ID),
		Email:        user.Email,
		Username:     user.Username,
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		TokenType:    tokenPair.TokenType,
		ExpiresIn:    tokenPair.ExpiresIn,
		ExpiresAt:    tokenPair.ExpiresAt,
	}, nil
}

// Logout invalidates user session tokens
func (s *authService) Logout(ctx context.Context, req *interfaces.LogoutRequest) error {
	var tokenToRevoke string
	var userID string

	// Determine which token to use for logout
	if req.AccessToken != "" {
		tokenToRevoke = req.AccessToken
	} else if req.RefreshToken != "" {
		tokenToRevoke = req.RefreshToken
	} else {
		return errors.New(errors.ErrorTypeValidation, "MISSING_TOKEN", "Either access_token or refresh_token must be provided")
	}

	// Get token claims to identify user
	claims, err := s.tokenService.GetTokenClaims(ctx, tokenToRevoke)
	if err != nil {
		return ErrInvalidToken.WithCause(err)
	}
	userID = claims.UserID

	// Revoke the specific token
	if err := s.tokenService.RevokeToken(ctx, tokenToRevoke); err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, "TOKEN_REVOCATION_FAILED", "Failed to revoke token")
	}

	// If all sessions should be logged out, revoke all user tokens
	if req.AllSessions {
		if err := s.blacklistRepo.BlacklistUserTokens(ctx, userID, "user logout all sessions"); err != nil {
			return errors.Wrap(err, errors.ErrorTypeInternal, "SESSION_REVOCATION_FAILED", "Failed to revoke all sessions")
		}

		// Delete all user sessions
		if err := s.sessionRepo.DeleteUserSessions(ctx, userID); err != nil {
			// Log error but don't fail logout
		}
	} else {
		// Delete specific session
		tokenHash := s.hashToken(tokenToRevoke)
		sessions, err := s.sessionRepo.GetUserSessions(ctx, userID)
		if err == nil {
			for _, session := range sessions {
				if session.TokenHash == tokenHash {
					s.sessionRepo.DeleteSession(ctx, session.ID)
					break
				}
			}
		}
	}

	return nil
}

// RefreshToken generates new tokens using a valid refresh token
func (s *authService) RefreshToken(ctx context.Context, req *interfaces.RefreshTokenRequest) (*interfaces.TokenResponse, error) {
	// Validate refresh token
	claims, err := s.tokenService.ValidateToken(ctx, req.RefreshToken)
	if err != nil {
		return nil, ErrInvalidRefreshToken.WithCause(err)
	}

	// Check if token is refresh token
	if claims.TokenType != token.TokenTypeRefresh {
		return nil, ErrInvalidRefreshToken.WithDetails("Token is not a refresh token")
	}

	// Check if token is blacklisted
	isBlacklisted, err := s.tokenService.IsTokenRevoked(ctx, claims.JTI)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "BLACKLIST_CHECK_FAILED", "Failed to check token blacklist")
	}
	if isBlacklisted {
		return nil, ErrTokenRevoked
	}

	// Get user to ensure they still exist and are not locked
	user, err := s.userRepo.GetUserByID(ctx, claims.UserID)
	if err != nil || user == nil {
		return nil, ErrUserNotFound
	}

	if user.AccountLocked {
		return nil, ErrAccountLocked
	}

	// Get updated user roles
	roles, err := s.userRepo.GetUserRoles(ctx, user.ID)
	if err != nil {
		roles = []string{} // Default to empty roles if error
	}

	// Generate new token pair
	newTokenClaims := token.TokenClaims{
		UserID:    user.ID,
		Email:     user.Email,
		Username:  user.Username,
		Roles:     roles,
		TokenType: token.TokenTypeAccess,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(s.config.Security.Token.AccessTTL),
		Issuer:    s.config.Security.Token.Issuer,
		Audience:  s.config.Security.Token.Audience,
		Subject:   user.ID,
		JTI:       uuid.New().String(),
	}

	tokenPair, err := s.tokenService.GenerateTokens(ctx, user.ID, newTokenClaims)
	if err != nil {
		return nil, ErrTokenGenerationFailed.WithCause(err)
	}

	// Revoke old refresh token
	s.tokenService.RevokeToken(ctx, req.RefreshToken)

	// Update session if exists
	tokenHash := s.hashToken(tokenPair.AccessToken)
	sessions, err := s.sessionRepo.GetUserSessions(ctx, user.ID)
	if err == nil {
		oldTokenHash := s.hashToken(req.RefreshToken)
		for _, session := range sessions {
			if session.TokenHash == oldTokenHash {
				session.TokenHash = tokenHash
				session.Roles = roles // Update roles in case they changed
				session.ExpiresAt = tokenPair.ExpiresAt.Unix()
				session.LastUsed = time.Now().Unix()
				s.sessionRepo.UpdateSession(ctx, session.ID, session)
				break
			}
		}
	}

	return &interfaces.TokenResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		TokenType:    tokenPair.TokenType,
		ExpiresIn:    tokenPair.ExpiresIn,
		ExpiresAt:    tokenPair.ExpiresAt,
	}, nil
}

// ValidateToken validates a token and returns its claims
func (s *authService) ValidateToken(ctx context.Context, req *interfaces.ValidateTokenRequest) (*interfaces.ValidateTokenResponse, error) {
	// Validate token format and signature
	claims, err := s.tokenService.ValidateToken(ctx, req.Token)
	if err != nil {
		return &interfaces.ValidateTokenResponse{Valid: false}, nil
	}

	// Check if token is blacklisted
	isBlacklisted, err := s.tokenService.IsTokenRevoked(ctx, claims.JTI)
	if err != nil {
		return &interfaces.ValidateTokenResponse{Valid: false}, nil
	}
	if isBlacklisted {
		return &interfaces.ValidateTokenResponse{Valid: false}, nil
	}

	// Check if user still exists and is not locked
	user, err := s.userRepo.GetUserByID(ctx, claims.UserID)
	if err != nil || user == nil || user.AccountLocked {
		return &interfaces.ValidateTokenResponse{Valid: false}, nil
	}

	// Convert claims to map for response
	claimsMap := map[string]interface{}{
		"user_id":    claims.UserID,
		"email":      claims.Email,
		"username":   claims.Username,
		"roles":      claims.Roles,
		"token_type": string(claims.TokenType),
		"issued_at":  claims.IssuedAt.Unix(),
		"expires_at": claims.ExpiresAt.Unix(),
		"issuer":     claims.Issuer,
		"audience":   claims.Audience,
		"subject":    claims.Subject,
		"jti":        claims.JTI,
	}

	return &interfaces.ValidateTokenResponse{
		Valid:     true,
		UserID:    claims.UserID,
		Email:     claims.Email,
		Username:  claims.Username,
		Roles:     claims.Roles,
		ExpiresAt: claims.ExpiresAt,
		Metadata:  claims.Metadata,
		Claims:    claimsMap,
	}, nil
}

// GetUserProfile retrieves user profile information from token
func (s *authService) GetUserProfile(ctx context.Context, tokenStr string) (*interfaces.UserProfile, error) {
	// Validate token
	claims, err := s.tokenService.ValidateToken(ctx, tokenStr)
	if err != nil {
		return nil, ErrInvalidToken.WithCause(err)
	}

	// Get user data
	user, err := s.userRepo.GetUserByID(ctx, claims.UserID)
	if err != nil || user == nil {
		return nil, ErrUserNotFound
	}

	// Decrypt sensitive data
	var firstName, lastName, phone string

	if len(user.FirstNameEncrypted) > 0 {
		if decrypted, err := s.encryptor.Decrypt(user.FirstNameEncrypted); err == nil {
			firstName = string(decrypted)
		}
	}

	if len(user.LastNameEncrypted) > 0 {
		if decrypted, err := s.encryptor.Decrypt(user.LastNameEncrypted); err == nil {
			lastName = string(decrypted)
		}
	}

	if len(user.PhoneEncrypted) > 0 {
		if decrypted, err := s.encryptor.Decrypt(user.PhoneEncrypted); err == nil {
			phone = string(decrypted)
		}
	}

	// Get user roles
	roles, err := s.userRepo.GetUserRoles(ctx, user.ID)
	if err != nil {
		roles = []string{}
	}

	return &interfaces.UserProfile{
		ID:        uuid.MustParse(user.ID),
		Email:     user.Email,
		Username:  user.Username,
		FirstName: firstName,
		LastName:  lastName,
		Phone:     phone,
		Roles:     roles,
		CreatedAt: time.Unix(user.CreatedAt, 0),
		UpdatedAt: time.Unix(user.UpdatedAt, 0),
	}, nil
}

// GetUserSessions retrieves active sessions for a user
func (s *authService) GetUserSessions(ctx context.Context, userID string) ([]*interfaces.SessionInfo, error) {
	sessions, err := s.sessionRepo.GetUserSessions(ctx, userID)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "SESSION_RETRIEVAL_FAILED", "Failed to retrieve user sessions")
	}

	var sessionInfos []*interfaces.SessionInfo
	for _, session := range sessions {
		sessionInfos = append(sessionInfos, &interfaces.SessionInfo{
			ID:        uuid.MustParse(session.ID),
			UserID:    uuid.MustParse(session.UserID),
			IPAddress: session.IPAddress,
			UserAgent: session.UserAgent,
			CreatedAt: time.Unix(session.CreatedAt, 0),
			LastUsed:  time.Unix(session.LastUsed, 0),
			ExpiresAt: time.Unix(session.ExpiresAt, 0),
		})
	}

	return sessionInfos, nil
}

// RevokeUserSessions revokes all sessions for a user
func (s *authService) RevokeUserSessions(ctx context.Context, userID string) error {
	// Blacklist all user tokens
	if err := s.blacklistRepo.BlacklistUserTokens(ctx, userID, "admin revoked all sessions"); err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, "TOKEN_REVOCATION_FAILED", "Failed to revoke user tokens")
	}

	// Delete all user sessions
	if err := s.sessionRepo.DeleteUserSessions(ctx, userID); err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, "SESSION_DELETION_FAILED", "Failed to delete user sessions")
	}

	return nil
}

// RevokeSession revokes a specific session
func (s *authService) RevokeSession(ctx context.Context, sessionID string) error {
	// Get session to find associated token
	session, err := s.sessionRepo.GetSession(ctx, sessionID)
	if err != nil {
		return ErrSessionNotFound.WithCause(err)
	}

	// Blacklist the token associated with this session
	if err := s.blacklistRepo.BlacklistToken(ctx, session.TokenHash, session.ExpiresAt, "session revoked"); err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, "TOKEN_BLACKLIST_FAILED", "Failed to blacklist session token")
	}

	// Delete the session
	if err := s.sessionRepo.DeleteSession(ctx, sessionID); err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, "SESSION_DELETION_FAILED", "Failed to delete session")
	}

	return nil
}

// Helper methods

func (s *authService) validateRegisterRequest(req *interfaces.RegisterRequest) error {
	if req.Email == "" {
		return ErrInvalidEmail
	}

	if !s.isValidEmail(req.Email) {
		return ErrInvalidEmail
	}

	if req.Password == "" || len(req.Password) < 8 {
		return ErrPasswordTooWeak
	}

	if req.Username != "" && !s.isValidUsername(req.Username) {
		return ErrInvalidUsername
	}

	return nil
}

func (s *authService) validateLoginRequest(req *interfaces.LoginRequest) error {
	if req.Email == "" && req.Username == "" {
		return ErrInvalidLoginRequest
	}

	if req.Password == "" {
		return ErrInvalidCredentials
	}

	if req.Email != "" && !s.isValidEmail(req.Email) {
		return ErrInvalidEmail
	}

	if req.Username != "" && !s.isValidUsername(req.Username) {
		return ErrInvalidUsername
	}

	return nil
}

func (s *authService) isValidEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

func (s *authService) isValidUsername(username string) bool {
	if len(username) < 3 || len(username) > 50 {
		return false
	}
	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	return usernameRegex.MatchString(username)
}

func (s *authService) hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func (s *authService) handleFailedLogin(ctx context.Context, user *interfaces.UserData) {
	failedAttempts := user.FailedAttempts + 1
	accountLocked := failedAttempts >= 5 // Lock after 5 failed attempts

	loginInfo := &interfaces.LoginInfo{
		FailedAttempts: failedAttempts,
		AccountLocked:  accountLocked,
		LastLoginAt:    user.LastLoginAt,
	}

	s.userRepo.UpdateUserLoginInfo(ctx, user.ID, loginInfo)
}
