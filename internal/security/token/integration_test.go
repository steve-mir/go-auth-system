package token

import (
	"context"
	"testing"
	"time"

	"github.com/steve-mir/go-auth-system/internal/config"
)

// TestTokenServiceIntegration tests the complete token workflow
func TestTokenServiceIntegration(t *testing.T) {
	testCases := []struct {
		name   string
		config *config.TokenConfig
	}{
		{
			name: "JWT Integration",
			config: &config.TokenConfig{
				Type:       "jwt",
				SigningKey: "integration-test-jwt-signing-key",
				AccessTTL:  time.Minute * 15,
				RefreshTTL: time.Hour * 24,
				Issuer:     "integration-test",
				Audience:   "integration-test-users",
			},
		},
		{
			name: "Paseto Integration",
			config: &config.TokenConfig{
				Type:          "paseto",
				EncryptionKey: "integration-test-32-character-key",
				AccessTTL:     time.Minute * 15,
				RefreshTTL:    time.Hour * 24,
				Issuer:        "integration-test",
				Audience:      "integration-test-users",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create service
			factory := NewFactory(tc.config)
			service, err := factory.CreateTokenService()
			if err != nil {
				t.Fatalf("Failed to create service: %v", err)
			}

			ctx := context.Background()

			// Test complete workflow
			t.Run("Complete Workflow", func(t *testing.T) {
				// 1. Generate tokens
				claims := TokenClaims{
					Email:    "integration@test.com",
					Username: "integrationuser",
					Roles:    []string{"user", "tester"},
					Metadata: map[string]string{
						"test_type": "integration",
						"version":   "1.0",
					},
				}

				tokenPair, err := service.GenerateTokens(ctx, "integration-user-123", claims)
				if err != nil {
					t.Fatalf("GenerateTokens failed: %v", err)
				}

				// Verify token pair structure
				if tokenPair.AccessToken == "" {
					t.Error("AccessToken is empty")
				}
				if tokenPair.RefreshToken == "" {
					t.Error("RefreshToken is empty")
				}
				if tokenPair.TokenType != "Bearer" {
					t.Errorf("TokenType = %v, want Bearer", tokenPair.TokenType)
				}

				// 2. Validate access token
				validatedClaims, err := service.ValidateToken(ctx, tokenPair.AccessToken)
				if err != nil {
					t.Fatalf("ValidateToken failed: %v", err)
				}

				// Verify claims
				if validatedClaims.UserID != "integration-user-123" {
					t.Errorf("UserID = %v, want integration-user-123", validatedClaims.UserID)
				}
				if validatedClaims.Email != claims.Email {
					t.Errorf("Email = %v, want %v", validatedClaims.Email, claims.Email)
				}
				if validatedClaims.TokenType != TokenTypeAccess {
					t.Errorf("TokenType = %v, want %v", validatedClaims.TokenType, TokenTypeAccess)
				}

				// 3. Refresh tokens
				newTokenPair, err := service.RefreshToken(ctx, tokenPair.RefreshToken)
				if err != nil {
					t.Fatalf("RefreshToken failed: %v", err)
				}

				// Verify new tokens are different
				if newTokenPair.AccessToken == tokenPair.AccessToken {
					t.Error("New access token should be different")
				}
				if newTokenPair.RefreshToken == tokenPair.RefreshToken {
					t.Error("New refresh token should be different")
				}

				// 4. Validate new access token
				newValidatedClaims, err := service.ValidateToken(ctx, newTokenPair.AccessToken)
				if err != nil {
					t.Fatalf("ValidateToken for new token failed: %v", err)
				}

				// Verify claims are preserved
				if newValidatedClaims.UserID != validatedClaims.UserID {
					t.Error("UserID should be preserved after refresh")
				}
				if newValidatedClaims.Email != validatedClaims.Email {
					t.Error("Email should be preserved after refresh")
				}

				// 5. Revoke token
				err = service.RevokeToken(ctx, newTokenPair.AccessToken)
				if err != nil {
					t.Fatalf("RevokeToken failed: %v", err)
				}

				// 6. Verify revoked token is invalid
				_, err = service.ValidateToken(ctx, newTokenPair.AccessToken)
				if err == nil {
					t.Error("Revoked token should be invalid")
				}

				// Verify it's a revocation error
				if tokenErr, ok := err.(*TokenError); ok {
					if tokenErr.Type != ErrorTypeRevoked {
						t.Errorf("Expected revocation error, got %v", tokenErr.Type)
					}
				}
			})

			// Test error scenarios
			t.Run("Error Scenarios", func(t *testing.T) {
				// Invalid token format
				_, err := service.ValidateToken(ctx, "invalid-token")
				if err == nil {
					t.Error("Should fail for invalid token format")
				}

				// Empty token
				_, err = service.ValidateToken(ctx, "")
				if err == nil {
					t.Error("Should fail for empty token")
				}

				// Try to refresh with access token
				claims := TokenClaims{Email: "test@example.com"}
				tokenPair, err := service.GenerateTokens(ctx, "test-user", claims)
				if err != nil {
					t.Fatalf("GenerateTokens failed: %v", err)
				}

				_, err = service.RefreshToken(ctx, tokenPair.AccessToken)
				if err == nil {
					t.Error("Should fail when trying to refresh with access token")
				}
			})

			// Test token expiration
			t.Run("Token Expiration", func(t *testing.T) {
				// Create service with very short TTL
				shortTTLConfig := *tc.config
				shortTTLConfig.AccessTTL = time.Millisecond * 100

				shortTTLFactory := NewFactory(&shortTTLConfig)
				shortTTLService, err := shortTTLFactory.CreateTokenService()
				if err != nil {
					t.Fatalf("Failed to create short TTL service: %v", err)
				}

				// Generate token
				claims := TokenClaims{Email: "expiry@test.com"}
				tokenPair, err := shortTTLService.GenerateTokens(ctx, "expiry-user", claims)
				if err != nil {
					t.Fatalf("GenerateTokens failed: %v", err)
				}

				// Wait for expiration
				time.Sleep(time.Millisecond * 200)

				// Token should be expired
				_, err = shortTTLService.ValidateToken(ctx, tokenPair.AccessToken)
				if err == nil {
					t.Error("Token should be expired")
				}

				// Verify it's an expiration error
				if tokenErr, ok := err.(*TokenError); ok {
					if tokenErr.Type != ErrorTypeExpired {
						t.Errorf("Expected expiration error, got %v", tokenErr.Type)
					}
				}
			})

			// Test GetTokenClaims
			t.Run("GetTokenClaims", func(t *testing.T) {
				claims := TokenClaims{
					Email:    "claims@test.com",
					Username: "claimsuser",
					Roles:    []string{"admin"},
					Metadata: map[string]string{"key": "value"},
				}

				tokenPair, err := service.GenerateTokens(ctx, "claims-user", claims)
				if err != nil {
					t.Fatalf("GenerateTokens failed: %v", err)
				}

				extractedClaims, err := service.GetTokenClaims(ctx, tokenPair.AccessToken)
				if err != nil {
					t.Fatalf("GetTokenClaims failed: %v", err)
				}

				// Verify extracted claims
				if extractedClaims.UserID != "claims-user" {
					t.Errorf("UserID = %v, want claims-user", extractedClaims.UserID)
				}
				if extractedClaims.Email != claims.Email {
					t.Errorf("Email = %v, want %v", extractedClaims.Email, claims.Email)
				}
			})
		})
	}
}

// TestFactoryValidation tests factory configuration validation
func TestFactoryValidation(t *testing.T) {
	testCases := []struct {
		name        string
		config      *config.TokenConfig
		expectError bool
		errorText   string
	}{
		{
			name:        "nil config",
			config:      nil,
			expectError: true,
			errorText:   "token configuration is required",
		},
		{
			name: "missing type",
			config: &config.TokenConfig{
				AccessTTL:  time.Minute * 15,
				RefreshTTL: time.Hour * 24,
			},
			expectError: true,
			errorText:   "token type is required",
		},
		{
			name: "unsupported type",
			config: &config.TokenConfig{
				Type:       "unsupported",
				AccessTTL:  time.Minute * 15,
				RefreshTTL: time.Hour * 24,
			},
			expectError: true,
			errorText:   "unsupported token type",
		},
		{
			name: "zero access TTL",
			config: &config.TokenConfig{
				Type:       "jwt",
				SigningKey: "test-key",
				AccessTTL:  0,
				RefreshTTL: time.Hour * 24,
				Issuer:     "test",
				Audience:   "test",
			},
			expectError: true,
			errorText:   "access token TTL must be positive",
		},
		{
			name: "refresh TTL less than access TTL",
			config: &config.TokenConfig{
				Type:       "jwt",
				SigningKey: "test-key",
				AccessTTL:  time.Hour * 24,
				RefreshTTL: time.Minute * 15,
				Issuer:     "test",
				Audience:   "test",
			},
			expectError: true,
			errorText:   "refresh token TTL must be greater than access token TTL",
		},
		{
			name: "JWT missing signing key",
			config: &config.TokenConfig{
				Type:       "jwt",
				AccessTTL:  time.Minute * 15,
				RefreshTTL: time.Hour * 24,
				Issuer:     "test",
				Audience:   "test",
			},
			expectError: true,
			errorText:   "JWT signing key is required",
		},
		{
			name: "Paseto missing encryption key",
			config: &config.TokenConfig{
				Type:       "paseto",
				AccessTTL:  time.Minute * 15,
				RefreshTTL: time.Hour * 24,
				Issuer:     "test",
				Audience:   "test",
			},
			expectError: true,
			errorText:   "Paseto encryption key is required",
		},
		{
			name: "Paseto short encryption key",
			config: &config.TokenConfig{
				Type:          "paseto",
				EncryptionKey: "short",
				AccessTTL:     time.Minute * 15,
				RefreshTTL:    time.Hour * 24,
				Issuer:        "test",
				Audience:      "test",
			},
			expectError: true,
			errorText:   "Paseto encryption key must be at least 32 characters",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			factory := NewFactory(tc.config)
			_, err := factory.CreateTokenService()

			if tc.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				} else if !contains(err.Error(), tc.errorText) {
					t.Errorf("Error %v should contain %v", err.Error(), tc.errorText)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestServiceTypeValidation tests service type validation
func TestServiceTypeValidation(t *testing.T) {
	testCases := []struct {
		serviceType string
		expectError bool
	}{
		{"jwt", false},
		{"JWT", false},
		{"paseto", false},
		{"PASETO", false},
		{"PaSeTO", false},
		{"invalid", true},
		{"", true},
	}

	for _, tc := range testCases {
		t.Run(tc.serviceType, func(t *testing.T) {
			err := ValidateServiceType(tc.serviceType)
			if (err != nil) != tc.expectError {
				t.Errorf("ValidateServiceType(%v) error = %v, expectError = %v",
					tc.serviceType, err, tc.expectError)
			}
		})
	}
}

// TestConfigBuilder tests the configuration builder
// func TestConfigBuilder(t *testing.T) {
// 	config := NewConfigBuilder().
// 		WithType("paseto").
// 		WithAccessTTL(time.Minute * 30).
// 		WithRefreshTTL(time.Hour * 48).
// 		WithEncryptionKey("builder-test-32-character-key-here").
// 		WithIssuer("builder-test").
// 		WithAudience("builder-users").
// 		Build()

// 	if config.Type != "paseto" {
// 		t.Errorf("Type = %v, want paseto", config.Type)
// 	}
// 	if config.AccessTTL != time.Minute*30 {
// 		t.Errorf("AccessTTL = %v, want %v", config.AccessTTL, time.Minute*30)
// 	}
// 	if config.RefreshTTL != time.Hour*48 {
// 		t.Errorf("RefreshTTL = %v, want %v", config.RefreshTTL, time.Hour*48)
// 	}
// 	if config.EncryptionKey != "builder-test-32-character-key-here" {
// 		t.Errorf("EncryptionKey = %v, want builder-test-32-character-key-here", config.EncryptionKey)
// 	}
// 	if config.Issuer != "builder-test" {
// 		t.Errorf("Issuer = %v, want builder-test", config.Issuer)
// 	}
// 	if config.Audience != "builder-users" {
// 		t.Errorf("Audience = %v, want builder-users", config.Audience)
// 	}
// }

// TestServiceInfo tests service information retrieval
func TestServiceInfo(t *testing.T) {
	serviceInfo := GetServiceInfo()

	if len(serviceInfo) != 2 {
		t.Errorf("Expected 2 services, got %d", len(serviceInfo))
	}

	// Verify JWT and Paseto info are present
	var jwtFound, pasetoFound bool
	for _, info := range serviceInfo {
		if info.Type == ServiceTypeJWT {
			jwtFound = true
			if info.Name == "" {
				t.Error("JWT service info missing name")
			}
			if info.Description == "" {
				t.Error("JWT service info missing description")
			}
			if len(info.Features) == 0 {
				t.Error("JWT service info missing features")
			}
		} else if info.Type == ServiceTypePaseto {
			pasetoFound = true
			if info.Name == "" {
				t.Error("Paseto service info missing name")
			}
			if info.Description == "" {
				t.Error("Paseto service info missing description")
			}
			if len(info.Features) == 0 {
				t.Error("Paseto service info missing features")
			}
		}
	}

	if !jwtFound {
		t.Error("JWT service info not found")
	}
	if !pasetoFound {
		t.Error("Paseto service info not found")
	}
}
