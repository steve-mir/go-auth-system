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
	oidcProviders     map[string]*OIDCProvider
	stateStore        StateStore
	hashService       hash.HashService
	encryptor         crypto.Encryptor
	samlService       *SAMLService
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
		oidcProviders:     make(map[string]*OIDCProvider),
		stateStore:        stateStore,
		hashService:       hashService,
		encryptor:         encryptor,
	}

	// Initialize OAuth providers
	service.initializeProviders()

	// Initialize OIDC providers
	service.initializeOIDCProviders()

	// Initialize SAML service if enabled
	if cfg.Features.EnterpriseSSO.SAML.Enabled {
		samlConfig := service.buildSAMLConfig(cfg)
		service.samlService = NewSAMLService(samlConfig, stateStore)
	}

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

// initializeOIDCProviders initializes OIDC providers based on configuration
func (s *ssoService) initializeOIDCProviders() {
	// OIDC provider
	if s.config.Features.EnterpriseSSO.OIDC.Enabled {
		oidcConfig := OIDCProviderConfig{
			Name:         "oidc",
			IssuerURL:    s.config.Features.EnterpriseSSO.OIDC.IssuerURL,
			ClientID:     s.config.Features.EnterpriseSSO.OIDC.ClientID,
			ClientSecret: s.config.Features.EnterpriseSSO.OIDC.ClientSecret,
			RedirectURL:  s.config.Features.EnterpriseSSO.OIDC.RedirectURL,
			Scopes:       s.config.Features.EnterpriseSSO.OIDC.Scopes,
			ClaimsMapping: OIDCClaimsMapping{
				Email:     "email",
				FirstName: "given_name",
				LastName:  "family_name",
				FullName:  "name",
				Groups:    "groups",
				Roles:     "roles",
				Username:  "preferred_username",
			},
		}

		// Set default scopes if not configured
		if len(oidcConfig.Scopes) == 0 {
			oidcConfig.Scopes = []string{"openid", "email", "profile"}
		}

		provider, err := NewOIDCProvider(oidcConfig)
		if err != nil {
			// Log error but don't fail service initialization
			fmt.Printf("Failed to initialize OIDC provider: %v\n", err)
		} else {
			s.oidcProviders["oidc"] = provider
		}
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

// SAML 2.0 Service Provider methods

// GetSAMLMetadata returns SAML Service Provider metadata
func (s *ssoService) GetSAMLMetadata(ctx context.Context) ([]byte, error) {
	if s.samlService == nil {
		return nil, fmt.Errorf("SAML service not enabled")
	}
	return s.samlService.GetMetadata(ctx)
}

// InitiateSAMLLogin initiates SAML authentication with an Identity Provider
func (s *ssoService) InitiateSAMLLogin(ctx context.Context, idpEntityID string, relayState string) (*SAMLAuthRequest, error) {
	if s.samlService == nil {
		return nil, fmt.Errorf("SAML service not enabled")
	}
	return s.samlService.InitiateLogin(ctx, idpEntityID, relayState)
}

// HandleSAMLResponse processes SAML response from Identity Provider
func (s *ssoService) HandleSAMLResponse(ctx context.Context, samlResponse string, relayState string) (*SAMLResult, error) {
	if s.samlService == nil {
		return nil, fmt.Errorf("SAML service not enabled")
	}

	// Process SAML response
	result, err := s.samlService.HandleResponse(ctx, samlResponse, relayState)
	if err != nil {
		return nil, fmt.Errorf("failed to handle SAML response: %w", err)
	}

	// Check if user exists by email
	existingUser, err := s.userRepo.GetUserByEmail(ctx, result.Email)
	if err != nil && !isNotFoundError(err) {
		return nil, fmt.Errorf("failed to check existing user: %w", err)
	}

	if existingUser != nil {
		// User exists, update result with user ID
		result.UserID = existingUser.ID
		result.IsNewUser = false

		// Update user attributes from SAML if needed
		if err := s.syncUserAttributesFromSAML(ctx, existingUser, result); err != nil {
			return nil, fmt.Errorf("failed to sync user attributes: %w", err)
		}
	} else {
		// Create new user from SAML attributes
		newUser, err := s.createUserFromSAML(ctx, result)
		if err != nil {
			return nil, fmt.Errorf("failed to create user from SAML: %w", err)
		}

		result.UserID = newUser.ID
		result.IsNewUser = true
	}

	return result, nil
}

// ValidateSAMLAssertion validates a SAML assertion
func (s *ssoService) ValidateSAMLAssertion(ctx context.Context, assertion *SAMLAssertion) error {
	if s.samlService == nil {
		return fmt.Errorf("SAML service not enabled")
	}
	return s.samlService.ValidateAssertion(ctx, assertion)
}

// buildSAMLConfig builds SAML configuration from application config
func (s *ssoService) buildSAMLConfig(cfg *config.Config) *SAMLConfig {
	samlCfg := cfg.Features.EnterpriseSSO.SAML

	// Build service provider configuration
	sp := SAMLServiceProvider{
		EntityID:                    samlCfg.EntityID,
		AssertionConsumerServiceURL: samlCfg.ACSURL,
		X509Certificate:             samlCfg.Certificate,
		PrivateKey:                  samlCfg.PrivateKey,
		NameIDFormat:                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		WantAssertionsSigned:        true,
		AuthnRequestsSigned:         true,
	}

	// Default attribute mapping
	attributeMapping := SAMLAttributeMapping{
		Email:     "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
		FirstName: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
		LastName:  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
		FullName:  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
		Groups:    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups",
		Roles:     "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
	}

	return &SAMLConfig{
		ServiceProvider:    sp,
		IdentityProviders:  make(map[string]SAMLIdentityProvider), // Will be populated from metadata
		AttributeMapping:   attributeMapping,
		SessionTimeout:     3600, // 1 hour
		ClockSkewTolerance: 300,  // 5 minutes
		MaxAssertionAge:    3600, // 1 hour
	}
}

// createUserFromSAML creates a new user from SAML authentication result
func (s *ssoService) createUserFromSAML(ctx context.Context, samlResult *SAMLResult) (*UserData, error) {
	// Parse name from SAML attributes
	firstName, lastName := s.parseNameFromSAML(samlResult)

	// Create user data
	createUserData := &CreateUserData{
		Email:         samlResult.Email,
		Username:      "", // Username can be set later
		PasswordHash:  "", // No password for SAML users initially
		HashAlgorithm: s.config.Security.PasswordHash.Algorithm,
		FirstName:     firstName,
		LastName:      lastName,
		Phone:         "",
		EmailVerified: true, // SAML users are considered verified
		PhoneVerified: false,
	}

	// Create user
	newUser, err := s.userRepo.CreateUser(ctx, createUserData)
	if err != nil {
		return nil, err
	}

	return newUser, nil
}

// syncUserAttributesFromSAML synchronizes user attributes from SAML
func (s *ssoService) syncUserAttributesFromSAML(ctx context.Context, user *UserData, samlResult *SAMLResult) error {
	// Parse name from SAML attributes
	firstName, lastName := s.parseNameFromSAML(samlResult)

	// Check if we need to update user attributes
	needsUpdate := false
	updateData := &UpdateUserData{
		ID: user.ID,
	}

	// Decrypt current names to compare
	currentFirstName, currentLastName, err := s.decryptUserNames(user)
	if err != nil {
		return fmt.Errorf("failed to decrypt current user names: %w", err)
	}

	if currentFirstName != firstName {
		updateData.FirstName = firstName
		needsUpdate = true
	}

	if currentLastName != lastName {
		updateData.LastName = lastName
		needsUpdate = true
	}

	// Update user if needed
	if needsUpdate {
		if err := s.userRepo.UpdateUser(ctx, updateData); err != nil {
			return fmt.Errorf("failed to update user attributes: %w", err)
		}
	}

	return nil
}

// parseNameFromSAML parses name from SAML attributes
func (s *ssoService) parseNameFromSAML(samlResult *SAMLResult) (string, string) {
	// Try to get first and last name from attributes
	firstName := samlResult.Attributes[s.samlService.config.AttributeMapping.FirstName]
	lastName := samlResult.Attributes[s.samlService.config.AttributeMapping.LastName]

	// If we have both, return them
	if firstName != "" && lastName != "" {
		return firstName, lastName
	}

	// Try to get full name and parse it
	fullName := samlResult.Attributes[s.samlService.config.AttributeMapping.FullName]
	if fullName != "" {
		return s.parseName(fullName)
	}

	// Use the name from the result
	if samlResult.Name != "" {
		return s.parseName(samlResult.Name)
	}

	return "", ""
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

// OpenID Connect methods

// GetOIDCAuthURL generates OIDC authorization URL
func (s *ssoService) GetOIDCAuthURL(ctx context.Context, provider string, state string, nonce string) (string, error) {
	// Validate provider
	oidcProvider, exists := s.oidcProviders[provider]
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

	// Generate nonce if not provided
	if nonce == "" {
		var err error
		nonce, err = GenerateNonce()
		if err != nil {
			return "", fmt.Errorf("failed to generate nonce: %w", err)
		}
	}

	// Store state for validation (include nonce for validation)
	oauthState := &OAuthState{
		State:     state,
		Provider:  provider,
		ExpiresAt: time.Now().Add(10 * time.Minute), // State expires in 10 minutes
		CreatedAt: time.Now(),
	}

	if err := s.stateStore.StoreState(ctx, oauthState); err != nil {
		return "", fmt.Errorf("failed to store OIDC state: %w", err)
	}

	// Generate authorization URL
	authURL := oidcProvider.GetAuthURL(state, nonce)
	return authURL, nil
}

// HandleOIDCCallback handles OIDC callback and returns user information
func (s *ssoService) HandleOIDCCallback(ctx context.Context, provider, code, state string) (*OIDCResult, error) {
	// Validate provider
	oidcProvider, exists := s.oidcProviders[provider]
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

	// Exchange code for tokens
	tokenResp, err := oidcProvider.ExchangeCode(ctx, code)
	if err != nil {
		return nil, NewOAuthExchangeFailedError(provider, err)
	}

	// Validate ID token
	idTokenClaims, err := oidcProvider.ValidateIDToken(ctx, tokenResp.IDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to validate ID token: %w", err)
	}

	// Get additional user info if UserInfo endpoint is available
	var userInfo *OIDCUserInfo
	if tokenResp.AccessToken != "" {
		userInfo, err = oidcProvider.GetUserInfo(ctx, tokenResp.AccessToken)
		if err != nil {
			// UserInfo endpoint might not be available or accessible, continue with ID token claims
			userInfo = &OIDCUserInfo{
				Subject:       idTokenClaims.Subject,
				Email:         idTokenClaims.Email,
				EmailVerified: idTokenClaims.EmailVerified,
				Name:          idTokenClaims.Name,
				GivenName:     idTokenClaims.GivenName,
				FamilyName:    idTokenClaims.FamilyName,
				Picture:       idTokenClaims.Picture,
				Locale:        idTokenClaims.Locale,
				Groups:        idTokenClaims.Groups,
				Roles:         idTokenClaims.Roles,
			}
		}
	} else {
		// Use ID token claims as user info
		userInfo = &OIDCUserInfo{
			Subject:       idTokenClaims.Subject,
			Email:         idTokenClaims.Email,
			EmailVerified: idTokenClaims.EmailVerified,
			Name:          idTokenClaims.Name,
			GivenName:     idTokenClaims.GivenName,
			FamilyName:    idTokenClaims.FamilyName,
			Picture:       idTokenClaims.Picture,
			Locale:        idTokenClaims.Locale,
			Groups:        idTokenClaims.Groups,
			Roles:         idTokenClaims.Roles,
		}
	}

	// Check if user exists by email
	existingUser, err := s.userRepo.GetUserByEmail(ctx, userInfo.Email)
	if err != nil && !isNotFoundError(err) {
		return nil, fmt.Errorf("failed to check existing user: %w", err)
	}

	var result *OIDCResult
	if existingUser != nil {
		// User exists, update user attributes from OIDC if needed
		if err := s.syncUserAttributesFromOIDC(ctx, existingUser, userInfo); err != nil {
			return nil, fmt.Errorf("failed to sync user attributes: %w", err)
		}

		// Decrypt user names for response
		firstName, lastName, err := s.decryptUserNames(existingUser)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt user names: %w", err)
		}

		result = &OIDCResult{
			UserID:       existingUser.ID,
			Email:        existingUser.Email,
			Name:         firstName + " " + lastName,
			Subject:      userInfo.Subject,
			Provider:     provider,
			IsNewUser:    false,
			AccessToken:  tokenResp.AccessToken,
			RefreshToken: tokenResp.RefreshToken,
			IDToken:      tokenResp.IDToken,
			ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Unix(),
			Claims:       s.extractClaimsFromOIDC(userInfo, idTokenClaims),
		}
	} else {
		// Create new user from OIDC claims
		newUser, err := s.createUserFromOIDC(ctx, userInfo)
		if err != nil {
			return nil, NewUserCreationFailedError(err)
		}

		// Parse name for response
		firstName, lastName := s.parseNameFromOIDC(userInfo)

		result = &OIDCResult{
			UserID:       newUser.ID,
			Email:        newUser.Email,
			Name:         firstName + " " + lastName,
			Subject:      userInfo.Subject,
			Provider:     provider,
			IsNewUser:    true,
			AccessToken:  tokenResp.AccessToken,
			RefreshToken: tokenResp.RefreshToken,
			IDToken:      tokenResp.IDToken,
			ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Unix(),
			Claims:       s.extractClaimsFromOIDC(userInfo, idTokenClaims),
		}
	}

	return result, nil
}

// ValidateOIDCIDToken validates an OIDC ID token
func (s *ssoService) ValidateOIDCIDToken(ctx context.Context, provider, idToken string) (*OIDCIDTokenClaims, error) {
	// Validate provider
	oidcProvider, exists := s.oidcProviders[provider]
	if !exists {
		return nil, NewProviderNotSupportedError(provider)
	}

	// Validate ID token
	claims, err := oidcProvider.ValidateIDToken(ctx, idToken)
	if err != nil {
		return nil, fmt.Errorf("failed to validate ID token: %w", err)
	}

	return claims, nil
}

// RefreshOIDCToken refreshes an OIDC access token
func (s *ssoService) RefreshOIDCToken(ctx context.Context, provider, refreshToken string) (*OIDCTokenResponse, error) {
	// Validate provider
	oidcProvider, exists := s.oidcProviders[provider]
	if !exists {
		return nil, NewProviderNotSupportedError(provider)
	}

	// Refresh token
	tokenResp, err := oidcProvider.RefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh OIDC token: %w", err)
	}

	return tokenResp, nil
}

// createUserFromOIDC creates a new user from OIDC user information
func (s *ssoService) createUserFromOIDC(ctx context.Context, userInfo *OIDCUserInfo) (*UserData, error) {
	// Parse name from OIDC claims
	firstName, lastName := s.parseNameFromOIDC(userInfo)

	// Create user data
	createUserData := &CreateUserData{
		Email:         userInfo.Email,
		Username:      userInfo.PreferredUsername, // Use preferred username if available
		PasswordHash:  "",                         // No password for OIDC users initially
		HashAlgorithm: s.config.Security.PasswordHash.Algorithm,
		FirstName:     firstName,
		LastName:      lastName,
		Phone:         "",
		EmailVerified: userInfo.EmailVerified,
		PhoneVerified: false,
	}

	// Create user
	newUser, err := s.userRepo.CreateUser(ctx, createUserData)
	if err != nil {
		return nil, err
	}

	return newUser, nil
}

// syncUserAttributesFromOIDC synchronizes user attributes from OIDC
func (s *ssoService) syncUserAttributesFromOIDC(ctx context.Context, user *UserData, userInfo *OIDCUserInfo) error {
	// Parse name from OIDC claims
	firstName, lastName := s.parseNameFromOIDC(userInfo)

	// Check if we need to update user attributes
	needsUpdate := false
	updateData := &UpdateUserData{
		ID: user.ID,
	}

	// Decrypt current names to compare
	currentFirstName, currentLastName, err := s.decryptUserNames(user)
	if err != nil {
		return fmt.Errorf("failed to decrypt current user names: %w", err)
	}

	if currentFirstName != firstName {
		updateData.FirstName = firstName
		needsUpdate = true
	}

	if currentLastName != lastName {
		updateData.LastName = lastName
		needsUpdate = true
	}

	// Update username if available and different
	if userInfo.PreferredUsername != "" && user.Username != userInfo.PreferredUsername {
		updateData.Username = userInfo.PreferredUsername
		needsUpdate = true
	}

	// Update user if needed
	if needsUpdate {
		if err := s.userRepo.UpdateUser(ctx, updateData); err != nil {
			return fmt.Errorf("failed to update user attributes: %w", err)
		}
	}

	return nil
}

// parseNameFromOIDC parses name from OIDC user information
func (s *ssoService) parseNameFromOIDC(userInfo *OIDCUserInfo) (string, string) {
	// Try to get first and last name from specific claims
	if userInfo.GivenName != "" && userInfo.FamilyName != "" {
		return userInfo.GivenName, userInfo.FamilyName
	}

	// Try to parse full name
	if userInfo.Name != "" {
		return s.parseName(userInfo.Name)
	}

	return "", ""
}

// extractClaimsFromOIDC extracts relevant claims from OIDC user info and ID token
func (s *ssoService) extractClaimsFromOIDC(userInfo *OIDCUserInfo, idTokenClaims *OIDCIDTokenClaims) map[string]string {
	claims := make(map[string]string)

	if userInfo.Subject != "" {
		claims["sub"] = userInfo.Subject
	}
	if userInfo.Email != "" {
		claims["email"] = userInfo.Email
	}
	if userInfo.Name != "" {
		claims["name"] = userInfo.Name
	}
	if userInfo.GivenName != "" {
		claims["given_name"] = userInfo.GivenName
	}
	if userInfo.FamilyName != "" {
		claims["family_name"] = userInfo.FamilyName
	}
	if userInfo.Picture != "" {
		claims["picture"] = userInfo.Picture
	}
	if userInfo.Locale != "" {
		claims["locale"] = userInfo.Locale
	}
	if userInfo.PreferredUsername != "" {
		claims["preferred_username"] = userInfo.PreferredUsername
	}

	// Add groups and roles if available
	if len(userInfo.Groups) > 0 {
		claims["groups"] = strings.Join(userInfo.Groups, ",")
	}
	if len(userInfo.Roles) > 0 {
		claims["roles"] = strings.Join(userInfo.Roles, ",")
	}

	// Add custom claims from ID token
	if idTokenClaims.CustomClaims != nil {
		for key, value := range idTokenClaims.CustomClaims {
			if strValue, ok := value.(string); ok {
				claims[key] = strValue
			}
		}
	}

	return claims
}
