package token

import (
	"context"
	"testing"
	"time"

	"github.com/steve-mir/go-auth-system/internal/config"
)

func TestJWTService_NewJWTService(t *testing.T) {
	tests := []struct {
		name    string
		config  *config.TokenConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: &config.TokenConfig{
				Type:       "jwt",
				SigningKey: "test-signing-key",
				AccessTTL:  time.Minute * 15,
				RefreshTTL: time.Hour * 24 * 7,
				Issuer:     "test-issuer",
				Audience:   "test-audience",
			},
			wantErr: false,
		},
		{
			name: "missing signing key",
			config: &config.TokenConfig{
				Type:       "jwt",
				AccessTTL:  time.Minute * 15,
				RefreshTTL: time.Hour * 24 * 7,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, err := NewJWTService(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewJWTService() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && service == nil {
				t.Error("NewJWTService() returned nil service")
			}
		})
	}
}

func TestJWTService_GenerateTokens(t *testing.T) {
	service := createTestJWTService(t)
	ctx := context.Background()

	claims := TokenClaims{
		Email:    "test@example.com",
		Username: "testuser",
		Roles:    []string{"user", "admin"},
		Metadata: map[string]string{"key": "value"},
	}

	tokenPair, err := service.GenerateTokens(ctx, "user123", claims)
	if err != nil {
		t.Fatalf("GenerateTokens() error = %v", err)
	}

	// Validate token pair structure
	if tokenPair.AccessToken == "" {
		t.Error("AccessToken is empty")
	}
	if tokenPair.RefreshToken == "" {
		t.Error("RefreshToken is empty")
	}
	if tokenPair.TokenType != "Bearer" {
		t.Errorf("TokenType = %v, want Bearer", tokenPair.TokenType)
	}
	if tokenPair.ExpiresIn <= 0 {
		t.Error("ExpiresIn should be positive")
	}
	if tokenPair.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should not be zero")
	}

	// Validate that tokens are different
	if tokenPair.AccessToken == tokenPair.RefreshToken {
		t.Error("AccessToken and RefreshToken should be different")
	}
}

func TestJWTService_ValidateToken(t *testing.T) {
	service := createTestJWTService(t)
	ctx := context.Background()

	// Generate a token first
	claims := TokenClaims{
		Email:    "test@example.com",
		Username: "testuser",
		Roles:    []string{"user"},
	}

	tokenPair, err := service.GenerateTokens(ctx, "user123", claims)
	if err != nil {
		t.Fatalf("GenerateTokens() error = %v", err)
	}

	// Test valid token
	validatedClaims, err := service.ValidateToken(ctx, tokenPair.AccessToken)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	// Validate claims
	if validatedClaims.UserID != "user123" {
		t.Errorf("UserID = %v, want user123", validatedClaims.UserID)
	}
	if validatedClaims.Email != "test@example.com" {
		t.Errorf("Email = %v, want test@example.com", validatedClaims.Email)
	}
	if validatedClaims.TokenType != TokenTypeAccess {
		t.Errorf("TokenType = %v, want %v", validatedClaims.TokenType, TokenTypeAccess)
	}

	// Test invalid token
	_, err = service.ValidateToken(ctx, "invalid-token")
	if err == nil {
		t.Error("ValidateToken() should fail for invalid token")
	}

	// Test empty token
	_, err = service.ValidateToken(ctx, "")
	if err == nil {
		t.Error("ValidateToken() should fail for empty token")
	}
}

func TestJWTService_RefreshToken(t *testing.T) {
	service := createTestJWTService(t)
	ctx := context.Background()

	// Generate initial tokens
	claims := TokenClaims{
		Email:    "test@example.com",
		Username: "testuser",
		Roles:    []string{"user"},
	}

	tokenPair, err := service.GenerateTokens(ctx, "user123", claims)
	if err != nil {
		t.Fatalf("GenerateTokens() error = %v", err)
	}

	// Test refresh with valid refresh token
	newTokenPair, err := service.RefreshToken(ctx, tokenPair.RefreshToken)
	if err != nil {
		t.Fatalf("RefreshToken() error = %v", err)
	}

	// Validate new token pair
	if newTokenPair.AccessToken == "" {
		t.Error("New AccessToken is empty")
	}
	if newTokenPair.RefreshToken == "" {
		t.Error("New RefreshToken is empty")
	}

	// Tokens should be different from original
	if newTokenPair.AccessToken == tokenPair.AccessToken {
		t.Error("New AccessToken should be different from original")
	}
	if newTokenPair.RefreshToken == tokenPair.RefreshToken {
		t.Error("New RefreshToken should be different from original")
	}

	// Test refresh with access token (should fail)
	_, err = service.RefreshToken(ctx, tokenPair.AccessToken)
	if err == nil {
		t.Error("RefreshToken() should fail when using access token")
	}

	// Test refresh with invalid token
	_, err = service.RefreshToken(ctx, "invalid-token")
	if err == nil {
		t.Error("RefreshToken() should fail for invalid token")
	}
}

func TestJWTService_RevokeToken(t *testing.T) {
	service := createTestJWTService(t)
	ctx := context.Background()

	// Generate a token
	claims := TokenClaims{
		Email:    "test@example.com",
		Username: "testuser",
	}

	tokenPair, err := service.GenerateTokens(ctx, "user123", claims)
	if err != nil {
		t.Fatalf("GenerateTokens() error = %v", err)
	}

	// Token should be valid initially
	_, err = service.ValidateToken(ctx, tokenPair.AccessToken)
	if err != nil {
		t.Fatalf("Token should be valid initially: %v", err)
	}

	// Revoke the token
	err = service.RevokeToken(ctx, tokenPair.AccessToken)
	if err != nil {
		t.Fatalf("RevokeToken() error = %v", err)
	}

	// Token should be invalid after revocation
	_, err = service.ValidateToken(ctx, tokenPair.AccessToken)
	if err == nil {
		t.Error("Token should be invalid after revocation")
	}
}

func TestJWTService_GetTokenClaims(t *testing.T) {
	service := createTestJWTService(t)
	ctx := context.Background()

	// Generate a token
	originalClaims := TokenClaims{
		Email:    "test@example.com",
		Username: "testuser",
		Roles:    []string{"user", "admin"},
		Metadata: map[string]string{"key": "value"},
	}

	tokenPair, err := service.GenerateTokens(ctx, "user123", originalClaims)
	if err != nil {
		t.Fatalf("GenerateTokens() error = %v", err)
	}

	// Extract claims without validation
	extractedClaims, err := service.GetTokenClaims(ctx, tokenPair.AccessToken)
	if err != nil {
		t.Fatalf("GetTokenClaims() error = %v", err)
	}

	// Validate extracted claims
	if extractedClaims.UserID != "user123" {
		t.Errorf("UserID = %v, want user123", extractedClaims.UserID)
	}
	if extractedClaims.Email != originalClaims.Email {
		t.Errorf("Email = %v, want %v", extractedClaims.Email, originalClaims.Email)
	}
	if extractedClaims.Username != originalClaims.Username {
		t.Errorf("Username = %v, want %v", extractedClaims.Username, originalClaims.Username)
	}
	if len(extractedClaims.Roles) != len(originalClaims.Roles) {
		t.Errorf("Roles length = %v, want %v", len(extractedClaims.Roles), len(originalClaims.Roles))
	}
}

func TestJWTService_GetTokenType(t *testing.T) {
	service := createTestJWTService(t)

	tokenType := service.GetTokenType()
	if tokenType != "jwt" {
		t.Errorf("GetTokenType() = %v, want jwt", tokenType)
	}
}

func TestJWTService_ExpiredToken(t *testing.T) {
	// Create service with very short TTL
	config := &config.TokenConfig{
		Type:       "jwt",
		SigningKey: "test-signing-key",
		AccessTTL:  time.Millisecond * 100, // Very short TTL
		RefreshTTL: time.Second,
		Issuer:     "test-issuer",
		Audience:   "test-audience",
	}

	service, err := NewJWTService(config)
	if err != nil {
		t.Fatalf("NewJWTService() error = %v", err)
	}

	ctx := context.Background()
	claims := TokenClaims{
		Email: "test@example.com",
	}

	// Generate token
	tokenPair, err := service.GenerateTokens(ctx, "user123", claims)
	if err != nil {
		t.Fatalf("GenerateTokens() error = %v", err)
	}

	// Wait for token to expire
	time.Sleep(time.Millisecond * 200)

	// Token should be expired
	_, err = service.ValidateToken(ctx, tokenPair.AccessToken)
	if err == nil {
		t.Error("ValidateToken() should fail for expired token")
	}

	// Check that it's specifically an expiration error
	if tokenErr, ok := err.(*TokenError); ok {
		if tokenErr.Type != ErrorTypeExpired {
			t.Errorf("Expected expiration error, got %v", tokenErr.Type)
		}
	}
}

func TestJWTService_InvalidSigningKey(t *testing.T) {
	service := createTestJWTService(t)
	ctx := context.Background()

	// Generate token with original service
	claims := TokenClaims{
		Email: "test@example.com",
	}

	tokenPair, err := service.GenerateTokens(ctx, "user123", claims)
	if err != nil {
		t.Fatalf("GenerateTokens() error = %v", err)
	}

	// Create new service with different signing key
	differentConfig := &config.TokenConfig{
		Type:       "jwt",
		SigningKey: "different-signing-key",
		AccessTTL:  time.Minute * 15,
		RefreshTTL: time.Hour * 24,
		Issuer:     "test-issuer",
		Audience:   "test-audience",
	}

	differentService, err := NewJWTService(differentConfig)
	if err != nil {
		t.Fatalf("NewJWTService() error = %v", err)
	}

	// Token should be invalid with different signing key
	_, err = differentService.ValidateToken(ctx, tokenPair.AccessToken)
	if err == nil {
		t.Error("ValidateToken() should fail with different signing key")
	}
}

// Helper function to create a test JWT service
func createTestJWTService(t *testing.T) *JWTService {
	config := &config.TokenConfig{
		Type:       "jwt",
		SigningKey: "test-signing-key-for-testing-purposes",
		AccessTTL:  time.Minute * 15,
		RefreshTTL: time.Hour * 24 * 7,
		Issuer:     "test-issuer",
		Audience:   "test-audience",
	}

	service, err := NewJWTService(config)
	if err != nil {
		t.Fatalf("Failed to create test JWT service: %v", err)
	}

	return service
}
