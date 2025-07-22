package token_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/steve-mir/go-auth-system/internal/config"
	"github.com/steve-mir/go-auth-system/internal/security/token"
)

// ExampleFactory_CreateTokenService demonstrates how to create different token services
func ExampleFactory_CreateTokenService() {
	// JWT configuration
	jwtConfig := &config.TokenConfig{
		Type:       "jwt",
		SigningKey: "your-secret-signing-key",
		AccessTTL:  time.Minute * 15,
		RefreshTTL: time.Hour * 24 * 7,
		Issuer:     "my-app",
		Audience:   "my-app-users",
	}

	// Create JWT service
	jwtFactory := token.NewFactory(jwtConfig)
	jwtService, err := jwtFactory.CreateTokenService()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("JWT Service Type: %s\n", jwtService.GetTokenType())

	// Paseto configuration
	pasetoConfig := &config.TokenConfig{
		Type:          "paseto",
		EncryptionKey: "your-32-character-encryption-key",
		AccessTTL:     time.Minute * 15,
		RefreshTTL:    time.Hour * 24 * 7,
		Issuer:        "my-app",
		Audience:      "my-app-users",
	}

	// Create Paseto service
	pasetoFactory := token.NewFactory(pasetoConfig)
	pasetoService, err := pasetoFactory.CreateTokenService()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Paseto Service Type: %s\n", pasetoService.GetTokenType())

	// Output:
	// JWT Service Type: jwt
	// Paseto Service Type: paseto
}

// ExampleTokenService_GenerateTokens demonstrates token generation
func ExampleTokenService_GenerateTokens() {
	// Create a JWT service
	config := &config.TokenConfig{
		Type:       "jwt",
		SigningKey: "example-signing-key",
		AccessTTL:  time.Minute * 15,
		RefreshTTL: time.Hour * 24,
		Issuer:     "example-app",
		Audience:   "example-users",
	}

	factory := token.NewFactory(config)
	service, err := factory.CreateTokenService()
	if err != nil {
		log.Fatal(err)
	}

	// Define user claims
	claims := token.TokenClaims{
		Email:    "user@example.com",
		Username: "johndoe",
		Roles:    []string{"user", "premium"},
		Metadata: map[string]string{
			"department": "engineering",
			"level":      "senior",
		},
	}

	// Generate tokens
	ctx := context.Background()
	tokenPair, err := service.GenerateTokens(ctx, "user-123", claims)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Token Type: %s\n", tokenPair.TokenType)
	fmt.Printf("Expires In: %d seconds\n", tokenPair.ExpiresIn)
	fmt.Printf("Access Token Length: %d\n", len(tokenPair.AccessToken))
	fmt.Printf("Refresh Token Length: %d\n", len(tokenPair.RefreshToken))

	// Output:
	// Token Type: Bearer
	// Expires In: 900
	// Access Token Length: > 0
	// Refresh Token Length: > 0
}

// ExampleTokenService_ValidateToken demonstrates token validation
func ExampleTokenService_ValidateToken() {
	// Create service and generate token
	config := &config.TokenConfig{
		Type:       "jwt",
		SigningKey: "example-signing-key",
		AccessTTL:  time.Minute * 15,
		RefreshTTL: time.Hour * 24,
		Issuer:     "example-app",
		Audience:   "example-users",
	}

	factory := token.NewFactory(config)
	service, err := factory.CreateTokenService()
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	claims := token.TokenClaims{
		Email:    "user@example.com",
		Username: "johndoe",
		Roles:    []string{"user"},
	}

	tokenPair, err := service.GenerateTokens(ctx, "user-123", claims)
	if err != nil {
		log.Fatal(err)
	}

	// Validate the access token
	validatedClaims, err := service.ValidateToken(ctx, tokenPair.AccessToken)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("User ID: %s\n", validatedClaims.UserID)
	fmt.Printf("Email: %s\n", validatedClaims.Email)
	fmt.Printf("Token Type: %s\n", validatedClaims.TokenType)
	fmt.Printf("Roles: %v\n", validatedClaims.Roles)

	// Output:
	// User ID: user-123
	// Email: user@example.com
	// Token Type: access
	// Roles: [user]
}

// ExampleTokenService_RefreshToken demonstrates token refresh
func ExampleTokenService_RefreshToken() {
	// Create service and generate initial tokens
	config := &config.TokenConfig{
		Type:       "jwt",
		SigningKey: "example-signing-key",
		AccessTTL:  time.Minute * 15,
		RefreshTTL: time.Hour * 24,
		Issuer:     "example-app",
		Audience:   "example-users",
	}

	factory := token.NewFactory(config)
	service, err := factory.CreateTokenService()
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	claims := token.TokenClaims{
		Email:    "user@example.com",
		Username: "johndoe",
		Roles:    []string{"user"},
	}

	originalTokens, err := service.GenerateTokens(ctx, "user-123", claims)
	if err != nil {
		log.Fatal(err)
	}

	// Refresh tokens using the refresh token
	newTokens, err := service.RefreshToken(ctx, originalTokens.RefreshToken)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("New tokens generated: %t\n", newTokens.AccessToken != originalTokens.AccessToken)
	fmt.Printf("Token Type: %s\n", newTokens.TokenType)
	fmt.Printf("Expires In: %d seconds\n", newTokens.ExpiresIn)

	// Output:
	// New tokens generated: true
	// Token Type: Bearer
	// Expires In: 900
}

// ExampleConfigBuilder demonstrates using the configuration builder
func ExampleConfigBuilder() {
	// Build JWT configuration
	jwtConfig := token.NewConfigBuilder().
		WithType("jwt").
		WithAccessTTL(time.Minute * 30).
		WithRefreshTTL(time.Hour * 48).
		WithSigningKey("my-jwt-signing-key").
		WithIssuer("my-application").
		WithAudience("my-users").
		Build()

	fmt.Printf("JWT Config Type: %s\n", jwtConfig.Type)
	fmt.Printf("JWT Access TTL: %v\n", jwtConfig.AccessTTL)

	// Build Paseto configuration
	pasetoConfig := token.NewConfigBuilder().
		WithType("paseto").
		WithAccessTTL(time.Minute * 20).
		WithRefreshTTL(time.Hour * 72).
		WithEncryptionKey("my-32-character-paseto-key-here").
		WithIssuer("my-application").
		WithAudience("my-users").
		Build()

	fmt.Printf("Paseto Config Type: %s\n", pasetoConfig.Type)
	fmt.Printf("Paseto Access TTL: %v\n", pasetoConfig.AccessTTL)

	// Output:
	// JWT Config Type: jwt
	// JWT Access TTL: 30m0s
	// Paseto Config Type: paseto
	// Paseto Access TTL: 20m0s
}

// ExampleGetServiceInfo demonstrates getting information about supported services
func ExampleGetServiceInfo() {
	serviceInfo := token.GetServiceInfo()

	for _, info := range serviceInfo {
		fmt.Printf("Service: %s\n", info.Name)
		fmt.Printf("Type: %s\n", info.Type)
		fmt.Printf("Description: %s\n", info.Description)
		fmt.Printf("Features: %v\n", info.Features)
		fmt.Println("---")
	}

	// Output will show information about JWT and Paseto services
}

// ExampleTokenService_RevokeToken demonstrates token revocation
func ExampleTokenService_RevokeToken() {
	// Create service and generate token
	config := &config.TokenConfig{
		Type:       "jwt",
		SigningKey: "example-signing-key",
		AccessTTL:  time.Minute * 15,
		RefreshTTL: time.Hour * 24,
		Issuer:     "example-app",
		Audience:   "example-users",
	}

	factory := token.NewFactory(config)
	service, err := factory.CreateTokenService()
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	claims := token.TokenClaims{
		Email: "user@example.com",
	}

	tokenPair, err := service.GenerateTokens(ctx, "user-123", claims)
	if err != nil {
		log.Fatal(err)
	}

	// Token should be valid initially
	_, err = service.ValidateToken(ctx, tokenPair.AccessToken)
	fmt.Printf("Token valid before revocation: %t\n", err == nil)

	// Revoke the token
	err = service.RevokeToken(ctx, tokenPair.AccessToken)
	if err != nil {
		log.Fatal(err)
	}

	// Token should be invalid after revocation
	_, err = service.ValidateToken(ctx, tokenPair.AccessToken)
	fmt.Printf("Token valid after revocation: %t\n", err == nil)

	// Output:
	// Token valid before revocation: true
	// Token valid after revocation: false
}
