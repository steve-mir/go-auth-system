package sso

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/steve-mir/go-auth-system/internal/config"
)

// ExampleOIDCAuthentication demonstrates how to use OIDC authentication
func ExampleOIDCAuthentication() {
	// Example configuration for OIDC
	cfg := &config.Config{
		Features: config.FeaturesConfig{
			EnterpriseSSO: config.EnterpriseSSO{
				OIDC: config.OIDCConfig{
					Enabled:      true,
					IssuerURL:    "https://accounts.google.com", // Example: Google as OIDC provider
					ClientID:     "your-client-id",
					ClientSecret: "your-client-secret",
					RedirectURL:  "https://yourapp.com/auth/oidc/callback",
					Scopes:       []string{"openid", "email", "profile"},
				},
			},
		},
	}

	// Create mock repositories (in real usage, these would be actual implementations)
	userRepo := &mockUserRepository{}
	socialAccountRepo := &mockSocialAccountRepository{}
	stateStore := &mockStateStore{}

	// Create SSO service
	ssoService := NewSSOService(cfg, userRepo, socialAccountRepo, stateStore, nil, nil)

	ctx := context.Background()

	// Step 1: Generate OIDC authorization URL
	fmt.Println("=== Step 1: Generate OIDC Authorization URL ===")
	authURL, err := ssoService.GetOIDCAuthURL(ctx, "oidc", "", "")
	if err != nil {
		log.Printf("Failed to generate OIDC auth URL: %v", err)
		return
	}
	fmt.Printf("Authorization URL: %s\n", authURL)
	fmt.Println("User should be redirected to this URL to authenticate")

	// Step 2: Handle OIDC callback (after user authentication)
	fmt.Println("\n=== Step 2: Handle OIDC Callback ===")
	// In a real scenario, these values would come from the callback request
	authCode := "example-auth-code"
	state := "example-state"

	result, err := ssoService.HandleOIDCCallback(ctx, "oidc", authCode, state)
	if err != nil {
		log.Printf("Failed to handle OIDC callback: %v", err)
		return
	}

	fmt.Printf("Authentication successful!\n")
	fmt.Printf("User ID: %s\n", result.UserID)
	fmt.Printf("Email: %s\n", result.Email)
	fmt.Printf("Name: %s\n", result.Name)
	fmt.Printf("Subject: %s\n", result.Subject)
	fmt.Printf("Is New User: %t\n", result.IsNewUser)
	fmt.Printf("Access Token: %s\n", result.AccessToken)
	fmt.Printf("ID Token: %s\n", result.IDToken)

	// Step 3: Validate ID Token
	fmt.Println("\n=== Step 3: Validate ID Token ===")
	claims, err := ssoService.ValidateOIDCIDToken(ctx, "oidc", result.IDToken)
	if err != nil {
		log.Printf("Failed to validate ID token: %v", err)
		return
	}

	fmt.Printf("ID Token is valid!\n")
	fmt.Printf("Subject: %s\n", claims.Subject)
	fmt.Printf("Email: %s\n", claims.Email)
	fmt.Printf("Email Verified: %t\n", claims.EmailVerified)
	fmt.Printf("Expires At: %s\n", time.Unix(claims.ExpiresAt, 0).Format(time.RFC3339))

	// Step 4: Refresh Token (if refresh token is available)
	if result.RefreshToken != "" {
		fmt.Println("\n=== Step 4: Refresh Access Token ===")
		tokenResp, err := ssoService.RefreshOIDCToken(ctx, "oidc", result.RefreshToken)
		if err != nil {
			log.Printf("Failed to refresh token: %v", err)
			return
		}

		fmt.Printf("Token refreshed successfully!\n")
		fmt.Printf("New Access Token: %s\n", tokenResp.AccessToken)
		fmt.Printf("New ID Token: %s\n", tokenResp.IDToken)
		fmt.Printf("Expires In: %d seconds\n", tokenResp.ExpiresIn)
	}
}

// ExampleOIDCConfiguration demonstrates different OIDC provider configurations
func ExampleOIDCConfiguration() {
	fmt.Println("=== OIDC Provider Configuration Examples ===")

	// Example 1: Google as OIDC Provider
	fmt.Println("\n1. Google OIDC Configuration:")
	googleConfig := config.OIDCConfig{
		Enabled:      true,
		IssuerURL:    "https://accounts.google.com",
		ClientID:     "your-google-client-id.apps.googleusercontent.com",
		ClientSecret: "your-google-client-secret",
		RedirectURL:  "https://yourapp.com/auth/oidc/google/callback",
		Scopes:       []string{"openid", "email", "profile"},
	}
	fmt.Printf("Issuer URL: %s\n", googleConfig.IssuerURL)
	fmt.Printf("Scopes: %v\n", googleConfig.Scopes)

	// Example 2: Microsoft Azure AD as OIDC Provider
	fmt.Println("\n2. Azure AD OIDC Configuration:")
	azureConfig := config.OIDCConfig{
		Enabled:      true,
		IssuerURL:    "https://login.microsoftonline.com/your-tenant-id/v2.0",
		ClientID:     "your-azure-client-id",
		ClientSecret: "your-azure-client-secret",
		RedirectURL:  "https://yourapp.com/auth/oidc/azure/callback",
		Scopes:       []string{"openid", "email", "profile"},
	}
	fmt.Printf("Issuer URL: %s\n", azureConfig.IssuerURL)
	fmt.Printf("Scopes: %v\n", azureConfig.Scopes)

	// Example 3: Okta as OIDC Provider
	fmt.Println("\n3. Okta OIDC Configuration:")
	oktaConfig := config.OIDCConfig{
		Enabled:      true,
		IssuerURL:    "https://your-domain.okta.com/oauth2/default",
		ClientID:     "your-okta-client-id",
		ClientSecret: "your-okta-client-secret",
		RedirectURL:  "https://yourapp.com/auth/oidc/okta/callback",
		Scopes:       []string{"openid", "email", "profile", "groups"},
	}
	fmt.Printf("Issuer URL: %s\n", oktaConfig.IssuerURL)
	fmt.Printf("Scopes: %v\n", oktaConfig.Scopes)

	// Example 4: Auth0 as OIDC Provider
	fmt.Println("\n4. Auth0 OIDC Configuration:")
	auth0Config := config.OIDCConfig{
		Enabled:      true,
		IssuerURL:    "https://your-domain.auth0.com/",
		ClientID:     "your-auth0-client-id",
		ClientSecret: "your-auth0-client-secret",
		RedirectURL:  "https://yourapp.com/auth/oidc/auth0/callback",
		Scopes:       []string{"openid", "email", "profile"},
	}
	fmt.Printf("Issuer URL: %s\n", auth0Config.IssuerURL)
	fmt.Printf("Scopes: %v\n", auth0Config.Scopes)
}

// ExampleOIDCErrorHandling demonstrates error handling in OIDC flows
func ExampleOIDCErrorHandling() {
	fmt.Println("=== OIDC Error Handling Examples ===")

	cfg := &config.Config{
		Features: config.FeaturesConfig{
			EnterpriseSSO: config.EnterpriseSSO{
				OIDC: config.OIDCConfig{
					Enabled:      true,
					IssuerURL:    "https://invalid-issuer.com",
					ClientID:     "invalid-client-id",
					ClientSecret: "invalid-client-secret",
					RedirectURL:  "https://yourapp.com/callback",
					Scopes:       []string{"openid", "email"},
				},
			},
		},
	}

	userRepo := &mockUserRepository{}
	socialAccountRepo := &mockSocialAccountRepository{}
	stateStore := &mockStateStore{}

	ssoService := NewSSOService(cfg, userRepo, socialAccountRepo, stateStore, nil, nil)
	ctx := context.Background()

	// Example 1: Invalid provider
	fmt.Println("\n1. Invalid Provider Error:")
	_, err := ssoService.GetOIDCAuthURL(ctx, "invalid-provider", "", "")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}

	// Example 2: Invalid state
	fmt.Println("\n2. Invalid State Error:")
	_, err = ssoService.HandleOIDCCallback(ctx, "oidc", "code", "invalid-state")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}

	// Example 3: Invalid ID token
	fmt.Println("\n3. Invalid ID Token Error:")
	_, err = ssoService.ValidateOIDCIDToken(ctx, "oidc", "invalid-id-token")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}

	// Example 4: Invalid refresh token
	fmt.Println("\n4. Invalid Refresh Token Error:")
	_, err = ssoService.RefreshOIDCToken(ctx, "oidc", "invalid-refresh-token")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}

// ExampleOIDCClaimsMapping demonstrates how to work with OIDC claims
func ExampleOIDCClaimsMapping() {
	fmt.Println("=== OIDC Claims Mapping Examples ===")

	// Example claims from different providers
	fmt.Println("\n1. Standard OIDC Claims:")
	standardClaims := map[string]interface{}{
		"sub":            "user-123",
		"email":          "user@example.com",
		"email_verified": true,
		"name":           "John Doe",
		"given_name":     "John",
		"family_name":    "Doe",
		"picture":        "https://example.com/avatar.jpg",
		"locale":         "en-US",
	}

	for key, value := range standardClaims {
		fmt.Printf("%s: %v\n", key, value)
	}

	fmt.Println("\n2. Enterprise Claims (with groups/roles):")
	enterpriseClaims := map[string]interface{}{
		"sub":            "employee-456",
		"email":          "employee@company.com",
		"email_verified": true,
		"name":           "Jane Smith",
		"given_name":     "Jane",
		"family_name":    "Smith",
		"groups":         []string{"developers", "admins"},
		"roles":          []string{"user", "admin"},
		"department":     "Engineering",
		"employee_id":    "EMP-456",
	}

	for key, value := range enterpriseClaims {
		fmt.Printf("%s: %v\n", key, value)
	}

	fmt.Println("\n3. Custom Claims Mapping:")
	claimsMapping := OIDCClaimsMapping{
		Email:     "email",
		FirstName: "given_name",
		LastName:  "family_name",
		FullName:  "name",
		Groups:    "groups",
		Roles:     "roles",
		Username:  "preferred_username",
	}

	fmt.Printf("Email claim: %s\n", claimsMapping.Email)
	fmt.Printf("First name claim: %s\n", claimsMapping.FirstName)
	fmt.Printf("Last name claim: %s\n", claimsMapping.LastName)
	fmt.Printf("Groups claim: %s\n", claimsMapping.Groups)
	fmt.Printf("Roles claim: %s\n", claimsMapping.Roles)
}

// Mock implementations for examples (these would be real implementations in production)

type mockUserRepository struct{}

func (m *mockUserRepository) GetUserByEmail(ctx context.Context, email string) (*UserData, error) {
	// Return nil to simulate user not found (new user scenario)
	return nil, fmt.Errorf("user not found")
}

func (m *mockUserRepository) CreateUser(ctx context.Context, user *CreateUserData) (*UserData, error) {
	return &UserData{
		ID:            "user-123",
		Email:         user.Email,
		Username:      user.Username,
		EmailVerified: user.EmailVerified,
		CreatedAt:     time.Now().Unix(),
		UpdatedAt:     time.Now().Unix(),
	}, nil
}

func (m *mockUserRepository) UpdateUser(ctx context.Context, user *UpdateUserData) error {
	return nil
}

type mockSocialAccountRepository struct{}

func (m *mockSocialAccountRepository) CreateSocialAccount(ctx context.Context, account *SocialAccount) error {
	return nil
}

func (m *mockSocialAccountRepository) GetSocialAccountByProviderAndSocialID(ctx context.Context, provider, socialID string) (*SocialAccount, error) {
	return nil, fmt.Errorf("social account not found")
}

func (m *mockSocialAccountRepository) GetSocialAccountsByUserID(ctx context.Context, userID string) ([]*SocialAccount, error) {
	return []*SocialAccount{}, nil
}

func (m *mockSocialAccountRepository) GetSocialAccountByUserIDAndProvider(ctx context.Context, userID, provider string) (*SocialAccount, error) {
	return nil, fmt.Errorf("social account not found")
}

func (m *mockSocialAccountRepository) UpdateSocialAccount(ctx context.Context, account *SocialAccount) error {
	return nil
}

func (m *mockSocialAccountRepository) DeleteSocialAccount(ctx context.Context, userID, provider string) error {
	return nil
}

func (m *mockSocialAccountRepository) DeleteAllUserSocialAccounts(ctx context.Context, userID string) error {
	return nil
}

type mockStateStore struct{}

func (m *mockStateStore) StoreState(ctx context.Context, state *OAuthState) error {
	return nil
}

func (m *mockStateStore) GetState(ctx context.Context, stateKey string) (*OAuthState, error) {
	return &OAuthState{
		State:     stateKey,
		Provider:  "oidc",
		ExpiresAt: time.Now().Add(10 * time.Minute),
		CreatedAt: time.Now(),
	}, nil
}

func (m *mockStateStore) DeleteState(ctx context.Context, stateKey string) error {
	return nil
}
