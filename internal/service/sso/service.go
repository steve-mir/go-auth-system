package sso

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/steve-mir/go-auth-system/internal/config"
	"github.com/steve-mir/go-auth-system/internal/errors"
	"github.com/steve-mir/go-auth-system/internal/security/crypto"
	"github.com/steve-mir/go-auth-system/internal/security/hash"
)

// ssoService implements the SSOService interface
type ssoService struct {
	config            *config.Config
	userRepo          UserRepository
	socialAccountRepo SocialAccountRepository
	providers         map[string]OAuthProvider
	stateStore        StateStore
	hashService       hash.HashService
	encryptor         crypto.Encryptor
}

// StateStore defines the interface for storing OAuth states
type StateStore interface {
	StoreState(ctx context.Context, state *OAuthState) error
	GetState(ctx context.Context, stateKey string) (*OAuthState, error)
	DeleteState(ctx context.Context, stateKey string) error
}

// NewSSOService creates a new SSO service
func NewSSOService(
	cfg *config.Config,
	userRepo UserRepository,
	socialAccountRepo SocialAccountRepository,
	stateStore StateStore,
	hashService hash.HashService,
	encryptor crypto.Encryptor,
) SSOService {
	service := &ssoService{
		config:            cfg,
		userRepo:          userRepo,
		socialAccountRepo: socialAccountRepo,
		providers:         make(map[string]OAuthProvider),
		stateStore:        stateStore,
		hashService:       hashService,
		encryptor:         encryptor,
	}

	// Initialize OAuth providers
	service.initializeProviders()

	return service
}

// initializeProviders initializes OAuth providers based on configuration
func (s *ssoService) initializeProviders() {
	// Google OAuth
	if s.config.Features.SocialAuth.Google.Enabled {
		googleConfig := ProviderConfig{
			ClientID:     s.config.Features.SocialAuth.Google.ClientID,
			ClientSecret: s.config.Features.SocialAuth.Google.ClientSecret,
			RedirectURL:  s.config.Features.SocialAuth.Google.RedirectURL,
			Scopes:       s.config.Features.SocialAuth.Google.Scopes,
		}
		s.providers["google"] = NewGoogleProvider(googleConfig)
	}

	// Facebook OAuth
	if s.config.Features.SocialAuth.Facebook.Enabled {
		facebookConfig := ProviderConfig{
			ClientID:     s.config.Features.SocialAuth.Facebook.ClientID,
			ClientSecret: s.config.Features.SocialAuth.Facebook.ClientSecret,
			RedirectURL:  s.config.Features.SocialAuth.Facebook.RedirectURL,
			Scopes:       s.config.Features.SocialAuth.Facebook.Scopes,
		}
		s.providers["facebook"] = NewFacebookProvider(facebookConfig)
	}

	// GitHub OAuth
	if s.config.Features.SocialAuth.GitHub.Enabled {
		githubConfig := ProviderConfig{
			ClientID:     s.config.Features.SocialAuth.GitHub.ClientID,
			ClientSecret: s.config.Features.SocialAuth.GitHub.ClientSecret,
			RedirectURL:  s.config.Features.SocialAuth.GitHub.RedirectURL,
			Scopes:       s.config.Features.SocialAuth.GitHub.Scopes,
		}
		s.providers["github"] = NewGitHubProvider(githubConfig)
	}
}

// GetOAuthURL generates OAuth authorization URL
func (s *ssoService) GetOAuthURL(ctx context.Context, provider string, state string) (string, error) {
	// Validate provider
	oauthProvider, exists := s.providers[provider]
	if !exists {
		return "", NewProviderNotSupportedError(provider)
	}

	// Generate state if not provided
	if state == "" {
		var err error
		state, err = s.generateSecureState()
		if err != nil {
			return "", fmt.Errorf("failed to generate state: %w", err)
		}
	}

	// Store state for validation
	oauthState := &OAuthState{
		State:     state,
		Provider:  provider,
		ExpiresAt: time.Now().Add(10 * time.Minute), // State expires in 10 minutes
		CreatedAt: time.Now(),
	}

	if err := s.stateStore.StoreState(ctx, oauthState); err != nil {
		return "", fmt.Errorf("failed to store OAuth state: %w", err)
	}

	// Generate authorization URL
	authURL := oauthProvider.GetAuthURL(state)
	return authURL, nil
}

// HandleOAuthCallback handles OAuth callback and returns user information
func (s *ssoService) HandleOAuthCallback(ctx context.Context, provider, code, state string) (*OAuthResult, error) {
	// Validate provider
	oauthProvider, exists := s.providers[provider]
	if !exists {
		return nil, NewProviderNotSupportedError(provider)
	}

	// Validate state
	storedState, err := s.stateStore.GetState(ctx, state)
	if err != nil {
		return nil, NewInvalidStateError()
	}

	if storedState.Provider != provider {
		return nil, NewInvalidStateError()
	}

	if time.Now().After(storedState.ExpiresAt) {
		return nil, NewStateExpiredError()
	}

	// Clean up state
	_ = s.stateStore.DeleteState(ctx, state)

	// Exchange code for token
	token, err := oauthProvider.ExchangeCode(ctx, code)
	if err != nil {
		return nil, NewOAuthExchangeFailedError(provider, err)
	}

	// Get user info from provider
	userInfo, err := oauthProvider.GetUserInfo(ctx, token)
	if err != nil {
		return nil, NewUserInfoFailedError(provider, err)
	}

	// Check if social account already exists
	existingSocialAccount, err := s.socialAccountRepo.GetSocialAccountByProviderAndSocialID(ctx, provider, userInfo.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing social account: %w", err)
	}

	var result *OAuthResult
	if existingSocialAccount != nil {
		// Social account exists, get user info
		existingUser, err := s.userRepo.GetUserByEmail(ctx, existingSocialAccount.Email)
		if err != nil {
			return nil, fmt.Errorf("failed to get user for existing social account: %w", err)
		}

		// Update social account tokens
		existingSocialAccount.AccessToken = token.AccessToken
		existingSocialAccount.RefreshToken = token.RefreshToken
		if token.ExpiresIn > 0 {
			expiresAt := time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
			existingSocialAccount.ExpiresAt = &expiresAt
		}
		existingSocialAccount.UpdatedAt = time.Now()

		if err := s.socialAccountRepo.UpdateSocialAccount(ctx, existingSocialAccount); err != nil {
			return nil, fmt.Errorf("failed to update social account: %w", err)
		}

		// Decrypt user names for response
		firstName, lastName, err := s.decryptUserNames(existingUser)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt user names: %w", err)
		}

		result = &OAuthResult{
			UserID:       existingUser.ID,
			Email:        existingUser.Email,
			Name:         firstName + " " + lastName,
			Provider:     provider,
			SocialID:     userInfo.ID,
			IsNewUser:    false,
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			ExpiresAt:    time.Now().Add(time.Duration(token.ExpiresIn) * time.Second).Unix(),
			Metadata:     userInfo.Metadata,
		}
	} else {
		// Check if user exists by email
		existingUser, err := s.userRepo.GetUserByEmail(ctx, userInfo.Email)
		if err != nil && !isNotFoundError(err) {
			return nil, fmt.Errorf("failed to check existing user: %w", err)
		}

		if existingUser != nil {
			// User exists, link new social account
			if err := s.linkSocialAccountToUser(ctx, existingUser.ID, provider, userInfo, token); err != nil {
				return nil, NewAccountLinkingFailedError(err)
			}

			// Decrypt user names for response
			firstName, lastName, err := s.decryptUserNames(existingUser)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt user names: %w", err)
			}

			result = &OAuthResult{
				UserID:       existingUser.ID,
				Email:        existingUser.Email,
				Name:         firstName + " " + lastName,
				Provider:     provider,
				SocialID:     userInfo.ID,
				IsNewUser:    false,
				AccessToken:  token.AccessToken,
				RefreshToken: token.RefreshToken,
				ExpiresAt:    time.Now().Add(time.Duration(token.ExpiresIn) * time.Second).Unix(),
				Metadata:     userInfo.Metadata,
			}
		} else {
			// Create new user
			newUser, err := s.createUserFromSocialAuth(ctx, userInfo, provider)
			if err != nil {
				return nil, NewUserCreationFailedError(err)
			}

			// Link social account
			if err := s.linkSocialAccountToUser(ctx, newUser.ID, provider, userInfo, token); err != nil {
				return nil, NewAccountLinkingFailedError(err)
			}

			// Parse name for response
			firstName, lastName := s.parseName(userInfo.Name)

			result = &OAuthResult{
				UserID:       newUser.ID,
				Email:        newUser.Email,
				Name:         firstName + " " + lastName,
				Provider:     provider,
				SocialID:     userInfo.ID,
				IsNewUser:    true,
				AccessToken:  token.AccessToken,
				RefreshToken: token.RefreshToken,
				ExpiresAt:    time.Now().Add(time.Duration(token.ExpiresIn) * time.Second).Unix(),
				Metadata:     userInfo.Metadata,
			}
		}
	}

	return result, nil
}

// LinkSocialAccount links a social account to an existing user
func (s *ssoService) LinkSocialAccount(ctx context.Context, userID string, provider string, socialID string) error {
	// Validate provider
	if _, exists := s.providers[provider]; !exists {
		return NewProviderNotSupportedError(provider)
	}

	// Check if account is already linked to another user
	existingAccount, err := s.socialAccountRepo.GetSocialAccountByProviderAndSocialID(ctx, provider, socialID)
	if err != nil {
		return fmt.Errorf("failed to check existing social account: %w", err)
	}

	if existingAccount != nil && existingAccount.UserID != userID {
		return NewAccountAlreadyLinkedError(provider)
	}

	// Check if user already has this provider linked
	userAccount, err := s.socialAccountRepo.GetSocialAccountByUserIDAndProvider(ctx, userID, provider)
	if err != nil {
		return fmt.Errorf("failed to check user social account: %w", err)
	}

	if userAccount != nil {
		// Update existing account
		userAccount.SocialID = socialID
		userAccount.UpdatedAt = time.Now()
		return s.socialAccountRepo.UpdateSocialAccount(ctx, userAccount)
	}

	// Create new social account record
	socialAccount := &SocialAccount{
		ID:        uuid.New().String(),
		UserID:    userID,
		Provider:  provider,
		SocialID:  socialID,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	return s.socialAccountRepo.CreateSocialAccount(ctx, socialAccount)
}

// UnlinkSocialAccount unlinks a social account from a user
func (s *ssoService) UnlinkSocialAccount(ctx context.Context, userID string, provider string) error {
	// Validate provider
	if _, exists := s.providers[provider]; !exists {
		return NewProviderNotSupportedError(provider)
	}

	// Check if account is linked
	account, err := s.socialAccountRepo.GetSocialAccountByUserIDAndProvider(ctx, userID, provider)
	if err != nil {
		return fmt.Errorf("failed to check social account: %w", err)
	}

	if account == nil {
		return NewAccountNotLinkedError(provider)
	}

	// Remove social account
	return s.socialAccountRepo.DeleteSocialAccount(ctx, userID, provider)
}

// GetLinkedAccounts returns all linked social accounts for a user
func (s *ssoService) GetLinkedAccounts(ctx context.Context, userID string) ([]LinkedAccount, error) {
	accounts, err := s.socialAccountRepo.GetSocialAccountsByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get social accounts: %w", err)
	}

	linkedAccounts := make([]LinkedAccount, len(accounts))
	for i, account := range accounts {
		linkedAccounts[i] = LinkedAccount{
			Provider: account.Provider,
			SocialID: account.SocialID,
			Email:    account.Email,
			Name:     account.Name,
			LinkedAt: account.CreatedAt.Unix(),
		}
	}

	return linkedAccounts, nil
}

// createUserFromSocialAuth creates a new user from social authentication
func (s *ssoService) createUserFromSocialAuth(ctx context.Context, userInfo *UserInfo, provider string) (*UserData, error) {
	// Parse name
	firstName, lastName := s.parseName(userInfo.Name)

	// Create user data
	createUserData := &CreateUserData{
		Email:         userInfo.Email,
		Username:      "", // Username can be set later
		PasswordHash:  "", // No password for social auth users initially
		HashAlgorithm: s.config.Security.PasswordHash.Algorithm,
		FirstName:     firstName,
		LastName:      lastName,
		Phone:         "",
		EmailVerified: userInfo.Verified,
		PhoneVerified: false,
	}

	// Create user
	newUser, err := s.userRepo.CreateUser(ctx, createUserData)
	if err != nil {
		return nil, err
	}

	return newUser, nil
}

// linkSocialAccountToUser links a social account to a user with token information
func (s *ssoService) linkSocialAccountToUser(ctx context.Context, userID string, provider string, userInfo *UserInfo, token *OAuthToken) error {
	// Create social account record
	socialAccount := &SocialAccount{
		ID:           uuid.New().String(),
		UserID:       userID,
		Provider:     provider,
		SocialID:     userInfo.ID,
		Email:        userInfo.Email,
		Name:         userInfo.Name,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Metadata:     userInfo.Metadata,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if token.ExpiresIn > 0 {
		expiresAt := time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
		socialAccount.ExpiresAt = &expiresAt
	}

	return s.socialAccountRepo.CreateSocialAccount(ctx, socialAccount)
}

// decryptUserNames decrypts user first and last names
func (s *ssoService) decryptUserNames(user *UserData) (string, string, error) {
	var firstName, lastName string

	if len(user.FirstNameEncrypted) > 0 {
		decrypted, err := s.encryptor.Decrypt(user.FirstNameEncrypted)
		if err != nil {
			return "", "", fmt.Errorf("failed to decrypt first name: %w", err)
		}
		firstName = string(decrypted)
	}

	if len(user.LastNameEncrypted) > 0 {
		decrypted, err := s.encryptor.Decrypt(user.LastNameEncrypted)
		if err != nil {
			return "", "", fmt.Errorf("failed to decrypt last name: %w", err)
		}
		lastName = string(decrypted)
	}

	return firstName, lastName, nil
}

// parseName parses a full name into first and last name
func (s *ssoService) parseName(fullName string) (string, string) {
	if fullName == "" {
		return "", ""
	}

	parts := strings.Fields(fullName)
	if len(parts) == 0 {
		return "", ""
	}

	if len(parts) == 1 {
		return parts[0], ""
	}

	firstName := parts[0]
	lastName := strings.Join(parts[1:], " ")
	return firstName, lastName
}

// generateSecureState generates a cryptographically secure random state
func (s *ssoService) generateSecureState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// isNotFoundError checks if an error is a not found error
func isNotFoundError(err error) bool {
	// Check if it's a database not found error or our custom not found error
	if err == nil {
		return false
	}

	// Check for SQL no rows error
	if err.Error() == "sql: no rows in result set" {
		return true
	}

	// Check for our custom error type
	if appErr, ok := err.(*errors.AppError); ok {
		return appErr.Type == errors.ErrorTypeNotFound
	}

	return false
}
