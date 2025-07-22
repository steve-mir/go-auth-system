package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/steve-mir/go-auth-system/internal/config"
	"github.com/steve-mir/go-auth-system/internal/service/auth"
)

func main() {
	fmt.Println("Testing basic auth service compilation...")

	// Create test configuration
	cfg := &config.Config{
		Security: config.SecurityConfig{
			PasswordHash: config.PasswordHashConfig{
				Algorithm: "argon2",
				Argon2: config.Argon2Config{
					Memory:      64 * 1024,
					Iterations:  3,
					Parallelism: 2,
					SaltLength:  16,
					KeyLength:   32,
				},
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

	// Test basic service creation
	deps := &auth.Dependencies{
		UserRepo:      nil, // Will be nil for this test
		SessionRepo:   nil,
		BlacklistRepo: nil,
		TokenService:  nil,
		HashService:   nil,
		Encryptor:     nil,
	}

	authService := auth.NewAuthService(cfg, deps)
	if authService == nil {
		log.Fatal("Failed to create auth service")
	}

	fmt.Println("✓ Auth service created successfully")

	// Test basic request validation
	ctx := context.Background()

	// Test invalid registration request
	invalidReq := &auth.RegisterRequest{
		Email:    "invalid-email",
		Password: "123", // Too short
	}

	_, err := authService.Register(ctx, invalidReq)
	if err == nil {
		log.Fatal("Expected validation error for invalid request")
	}
	fmt.Println("✓ Request validation working correctly")

	fmt.Println("🎉 Basic integration test passed!")
}
