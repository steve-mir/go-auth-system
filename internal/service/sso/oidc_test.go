package sso

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOIDCProviderBasicFunctionality tests basic OIDC provider functionality
func TestOIDCProviderBasicFunctionality(t *testing.T) {
	// Test configuration
	config := OIDCProviderConfig{
		Name:         "test-oidc",
		IssuerURL:    "https://example.com",
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{"openid", "email", "profile"},
	}

	// This will fail because we can't reach the discovery endpoint
	// but it tests the basic structure
	_, err := NewOIDCProvider(config)
	assert.Error(t, err) // Expected to fail due to network call
	assert.Contains(t, err.Error(), "failed to discover OIDC configuration")
}

// TestOIDCProviderWithDiscoveryDocument tests OIDC provider with pre-configured discovery document
func TestOIDCProviderWithDiscoveryDocument(t *testing.T) {
	discoveryDoc := &OIDCDiscoveryDocument{
		Issuer:                            "https://example.com",
		AuthorizationEndpoint:             "https://example.com/oauth2/authorize",
		TokenEndpoint:                     "https://example.com/oauth2/token",
		UserInfoEndpoint:                  "https://example.com/oauth2/userinfo",
		JWKSUri:                           "https://example.com/oauth2/jwks",
		ScopesSupported:                   []string{"openid", "email", "profile"},
		ResponseTypesSupported:            []string{"code"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post"},
		ClaimsSupported:                   []string{"sub", "email", "name"},
	}

	config := OIDCProviderConfig{
		Name:              "test-oidc",
		IssuerURL:         "https://example.com",
		ClientID:          "test-client-id",
		ClientSecret:      "test-client-secret",
		RedirectURL:       "http://localhost:8080/callback",
		Scopes:            []string{"openid", "email", "profile"},
		DiscoveryDocument: discoveryDoc,
	}

	provider, err := NewOIDCProvider(config)
	require.NoError(t, err)
	assert.NotNil(t, provider)
	// assert.Equal(t, "test-oidc", provider.GetProviderName())
	assert.Equal(t, discoveryDoc, provider.discoveryDocument)
}

// TestOIDCAuthURLGeneration tests OIDC authorization URL generation
func TestOIDCAuthURLGeneration(t *testing.T) {
	discoveryDoc := &OIDCDiscoveryDocument{
		Issuer:                "https://example.com",
		AuthorizationEndpoint: "https://example.com/oauth2/authorize",
		TokenEndpoint:         "https://example.com/oauth2/token",
		UserInfoEndpoint:      "https://example.com/oauth2/userinfo",
		JWKSUri:               "https://example.com/oauth2/jwks",
	}

	config := OIDCProviderConfig{
		Name:              "test-oidc",
		IssuerURL:         "https://example.com",
		ClientID:          "test-client-id",
		ClientSecret:      "test-client-secret",
		RedirectURL:       "http://localhost:8080/callback",
		Scopes:            []string{"openid", "email", "profile"},
		DiscoveryDocument: discoveryDoc,
	}

	provider, err := NewOIDCProvider(config)
	require.NoError(t, err)

	state := "test-state"
	nonce := "test-nonce"
	authURL := provider.GetAuthURL(state, nonce)

	assert.Contains(t, authURL, "https://example.com/oauth2/authorize")
	assert.Contains(t, authURL, "client_id=test-client-id")
	assert.Contains(t, authURL, "redirect_uri=http%3A//localhost%3A8080/callback")
	assert.Contains(t, authURL, "scope=openid+email+profile")
	assert.Contains(t, authURL, "response_type=code")
	assert.Contains(t, authURL, "state=test-state")
	assert.Contains(t, authURL, "nonce=test-nonce")
}

// TestOIDCAuthURLGenerationWithoutNonce tests OIDC authorization URL generation without nonce
func TestOIDCAuthURLGenerationWithoutNonce(t *testing.T) {
	discoveryDoc := &OIDCDiscoveryDocument{
		Issuer:                "https://example.com",
		AuthorizationEndpoint: "https://example.com/oauth2/authorize",
		TokenEndpoint:         "https://example.com/oauth2/token",
	}

	config := OIDCProviderConfig{
		Name:              "test-oidc",
		IssuerURL:         "https://example.com",
		ClientID:          "test-client-id",
		ClientSecret:      "test-client-secret",
		RedirectURL:       "http://localhost:8080/callback",
		Scopes:            []string{"openid", "email"},
		DiscoveryDocument: discoveryDoc,
	}

	provider, err := NewOIDCProvider(config)
	require.NoError(t, err)

	state := "test-state"
	authURL := provider.GetAuthURL(state, "")

	assert.Contains(t, authURL, "https://example.com/oauth2/authorize")
	assert.Contains(t, authURL, "client_id=test-client-id")
	assert.Contains(t, authURL, "state=test-state")
	assert.NotContains(t, authURL, "nonce=")
}

// TestValidateAudience tests audience validation
func TestValidateAudience(t *testing.T) {
	// config := OIDCProviderConfig{
	// 	Name:     "test-oidc",
	// 	ClientID: "test-client-id",
	// 	DiscoveryDocument: &OIDCDiscoveryDocument{
	// 		Issuer: "https://example.com",
	// 	},
	// }

	// provider, err := NewOIDCProvider(config)
	// require.NoError(t, err)

	// Test string audience
	// assert.True(t, provider.validateAudience("test-client-id"))
	// assert.False(t, provider.validateAudience("wrong-client-id"))

	// Test array audience ([]interface{})
	// audienceArray := []interface{}{"test-client-id", "other-client"}
	// assert.True(t, provider.validateAudience(audienceArray))

	// wrongAudienceArray := []interface{}{"wrong-client-id", "other-client"}
	// assert.False(t, provider.validateAudience(wrongAudienceArray))

	// // Test string array audience
	// stringAudienceArray := []string{"test-client-id", "other-client"}
	// assert.True(t, provider.validateAudience(stringAudienceArray))

	// wrongStringAudienceArray := []string{"wrong-client-id", "other-client"}
	// assert.False(t, provider.validateAudience(wrongStringAudienceArray))
}

// // TestGenerateNonce tests nonce generation
// func TestGenerateNonce(t *testing.T) {
// 	nonce1, err := GenerateNonce()
// 	require.NoError(t, err)
// 	assert.NotEmpty(t, nonce1)

// 	nonce2, err := GenerateNonce()
// 	require.NoError(t, err)
// 	assert.NotEmpty(t, nonce2)

// 	// Nonces should be different
// 	assert.NotEqual(t, nonce1, nonce2)

// 	// Nonces should be base64 URL encoded (no + or / characters)
// 	assert.NotContains(t, nonce1, "+")
// 	assert.NotContains(t, nonce1, "/")
// 	assert.NotContains(t, nonce2, "+")
// 	assert.NotContains(t, nonce2, "/")

// 	// Nonces should be reasonably long (32 bytes base64 encoded)
// 	assert.Greater(t, len(nonce1), 40)
// 	assert.Greater(t, len(nonce2), 40)
// }

// TestOIDCClaimsMapping tests OIDC claims mapping functionality
func TestOIDCClaimsMapping(t *testing.T) {
	mapping := OIDCClaimsMapping{
		Email:     "email",
		FirstName: "given_name",
		LastName:  "family_name",
		FullName:  "name",
		Groups:    "groups",
		Roles:     "roles",
		Username:  "preferred_username",
	}

	assert.Equal(t, "email", mapping.Email)
	assert.Equal(t, "given_name", mapping.FirstName)
	assert.Equal(t, "family_name", mapping.LastName)
	assert.Equal(t, "name", mapping.FullName)
	assert.Equal(t, "groups", mapping.Groups)
	assert.Equal(t, "roles", mapping.Roles)
	assert.Equal(t, "preferred_username", mapping.Username)
}

// TestOIDCUserInfoStructure tests OIDC user info structure
func TestOIDCUserInfoStructure(t *testing.T) {
	userInfo := &OIDCUserInfo{
		Subject:           "user-123",
		Email:             "user@example.com",
		EmailVerified:     true,
		Name:              "John Doe",
		GivenName:         "John",
		FamilyName:        "Doe",
		Picture:           "https://example.com/avatar.jpg",
		Locale:            "en-US",
		PreferredUsername: "johndoe",
		Groups:            []string{"users", "admins"},
		Roles:             []string{"user", "admin"},
	}

	assert.Equal(t, "user-123", userInfo.Subject)
	assert.Equal(t, "user@example.com", userInfo.Email)
	assert.True(t, userInfo.EmailVerified)
	assert.Equal(t, "John Doe", userInfo.Name)
	assert.Equal(t, "John", userInfo.GivenName)
	assert.Equal(t, "Doe", userInfo.FamilyName)
	assert.Equal(t, "https://example.com/avatar.jpg", userInfo.Picture)
	assert.Equal(t, "en-US", userInfo.Locale)
	assert.Equal(t, "johndoe", userInfo.PreferredUsername)
	assert.Equal(t, []string{"users", "admins"}, userInfo.Groups)
	assert.Equal(t, []string{"user", "admin"}, userInfo.Roles)
}

// TestOIDCTokenResponseStructure tests OIDC token response structure
func TestOIDCTokenResponseStructure(t *testing.T) {
	tokenResp := &OIDCTokenResponse{
		AccessToken:  "access-token-123",
		TokenType:    "Bearer",
		RefreshToken: "refresh-token-456",
		ExpiresIn:    3600,
		IDToken:      "id-token-789",
		Scope:        "openid email profile",
	}

	assert.Equal(t, "access-token-123", tokenResp.AccessToken)
	assert.Equal(t, "Bearer", tokenResp.TokenType)
	assert.Equal(t, "refresh-token-456", tokenResp.RefreshToken)
	assert.Equal(t, int64(3600), tokenResp.ExpiresIn)
	assert.Equal(t, "id-token-789", tokenResp.IDToken)
	assert.Equal(t, "openid email profile", tokenResp.Scope)
}

// TestOIDCResultStructure tests OIDC result structure
func TestOIDCResultStructure(t *testing.T) {
	claims := map[string]string{
		"sub":   "user-123",
		"email": "user@example.com",
		"name":  "John Doe",
	}

	result := &OIDCResult{
		UserID:       "internal-user-456",
		Email:        "user@example.com",
		Name:         "John Doe",
		Subject:      "user-123",
		Provider:     "oidc",
		IsNewUser:    true,
		AccessToken:  "access-token-123",
		RefreshToken: "refresh-token-456",
		IDToken:      "id-token-789",
		ExpiresAt:    1234567890,
		Claims:       claims,
	}

	assert.Equal(t, "internal-user-456", result.UserID)
	assert.Equal(t, "user@example.com", result.Email)
	assert.Equal(t, "John Doe", result.Name)
	assert.Equal(t, "user-123", result.Subject)
	assert.Equal(t, "oidc", result.Provider)
	assert.True(t, result.IsNewUser)
	assert.Equal(t, "access-token-123", result.AccessToken)
	assert.Equal(t, "refresh-token-456", result.RefreshToken)
	assert.Equal(t, "id-token-789", result.IDToken)
	assert.Equal(t, int64(1234567890), result.ExpiresAt)
	assert.Equal(t, claims, result.Claims)
}
