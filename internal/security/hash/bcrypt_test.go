package hash

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/steve-mir/go-auth-system/internal/config"
)

func TestBcryptService_HashPassword(t *testing.T) {
	cfg := config.BcryptConfig{
		Cost: 12,
	}
	service := NewBcryptService(cfg)
	ctx := context.Background()

	tests := []struct {
		name        string
		password    string
		expectError bool
		errorType   error
	}{
		{
			name:        "valid password",
			password:    "validpassword123",
			expectError: false,
		},
		{
			name:        "minimum length password",
			password:    "12345678",
			expectError: false,
		},
		{
			name:        "password too short",
			password:    "1234567",
			expectError: true,
			errorType:   ErrPasswordTooShort,
		},
		{
			name:        "password too long",
			password:    strings.Repeat("a", MaxPasswordLength+1),
			expectError: true,
			errorType:   ErrPasswordTooLong,
		},
		{
			name:        "empty password",
			password:    "",
			expectError: true,
			errorType:   ErrPasswordTooShort,
		},
		{
			name:        "password with special characters",
			password:    "P@ssw0rd!#$%",
			expectError: false,
		},
		{
			name:        "password with unicode",
			password:    "пароль123",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := service.HashPassword(ctx, tt.password)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorType != nil && err != tt.errorType {
					t.Errorf("expected error %v, got %v", tt.errorType, err)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if hash == "" {
				t.Error("hash should not be empty")
				return
			}

			// Verify hash format (bcrypt format: $2a$cost$salt+hash)
			if !strings.HasPrefix(hash, "$2a$12$") {
				t.Errorf("hash should start with $2a$12$, got: %s", hash)
			}

			// Verify hash length (bcrypt hashes are always 60 characters)
			if len(hash) != 60 {
				t.Errorf("bcrypt hash should be 60 characters, got %d", len(hash))
			}
		})
	}
}

func TestBcryptService_VerifyPassword(t *testing.T) {
	cfg := config.BcryptConfig{
		Cost: 12,
	}
	service := NewBcryptService(cfg)
	ctx := context.Background()

	password := "testpassword123"
	hash, err := service.HashPassword(ctx, password)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	tests := []struct {
		name        string
		password    string
		hash        string
		expectError bool
		errorType   error
	}{
		{
			name:        "correct password",
			password:    password,
			hash:        hash,
			expectError: false,
		},
		{
			name:        "incorrect password",
			password:    "wrongpassword",
			hash:        hash,
			expectError: true,
			errorType:   ErrHashMismatch,
		},
		{
			name:        "empty password",
			password:    "",
			hash:        hash,
			expectError: true,
			errorType:   ErrPasswordTooShort,
		},
		{
			name:        "invalid hash format",
			password:    password,
			hash:        "invalid_hash",
			expectError: true,
			errorType:   ErrInvalidHash,
		},
		{
			name:        "empty hash",
			password:    password,
			hash:        "",
			expectError: true,
			errorType:   ErrInvalidHash,
		},
		{
			name:        "argon2 hash",
			password:    password,
			hash:        "$argon2id$v=19$m=65536,t=3,p=2$invalid",
			expectError: true,
			errorType:   ErrInvalidHash,
		},
		{
			name:        "truncated hash",
			password:    password,
			hash:        "$2a$12$short",
			expectError: true,
			errorType:   ErrInvalidHash,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.VerifyPassword(ctx, tt.password, tt.hash)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorType != nil && !strings.Contains(err.Error(), tt.errorType.Error()) {
					t.Errorf("expected error containing %v, got %v", tt.errorType, err)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestBcryptService_NeedsRehash(t *testing.T) {
	cfg := config.BcryptConfig{
		Cost: 12,
	}
	service := NewBcryptService(cfg)
	ctx := context.Background()

	password := "testpassword123"
	hash, err := service.HashPassword(ctx, password)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	tests := []struct {
		name           string
		hash           string
		newCost        int
		expectedRehash bool
	}{
		{
			name:           "same cost",
			hash:           hash,
			newCost:        12,
			expectedRehash: false,
		},
		{
			name:           "higher cost",
			hash:           hash,
			newCost:        14,
			expectedRehash: true,
		},
		{
			name:           "lower cost",
			hash:           hash,
			newCost:        10,
			expectedRehash: true,
		},
		{
			name:           "invalid hash",
			hash:           "invalid_hash",
			newCost:        12,
			expectedRehash: true,
		},
		{
			name:           "empty hash",
			hash:           "",
			newCost:        12,
			expectedRehash: true,
		},
		{
			name:           "argon2 hash",
			hash:           "$argon2id$v=19$m=65536,t=3,p=2$salt$hash",
			newCost:        12,
			expectedRehash: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newService := NewBcryptService(config.BcryptConfig{Cost: tt.newCost})
			needsRehash := newService.NeedsRehash(ctx, tt.hash)

			if needsRehash != tt.expectedRehash {
				t.Errorf("expected needsRehash=%v, got %v", tt.expectedRehash, needsRehash)
			}
		})
	}
}

func TestBcryptService_HashConsistency(t *testing.T) {
	cfg := config.BcryptConfig{
		Cost: 12,
	}
	service := NewBcryptService(cfg)
	ctx := context.Background()

	password := "consistencytest123"

	// Generate multiple hashes of the same password
	hashes := make([]string, 5)
	for i := 0; i < 5; i++ {
		hash, err := service.HashPassword(ctx, password)
		if err != nil {
			t.Fatalf("failed to hash password: %v", err)
		}
		hashes[i] = hash
	}

	// All hashes should be different (due to random salt)
	for i := 0; i < len(hashes); i++ {
		for j := i + 1; j < len(hashes); j++ {
			if hashes[i] == hashes[j] {
				t.Errorf("hashes should be different due to random salt, but got identical hashes")
			}
		}
	}

	// All hashes should verify the same password
	for i, hash := range hashes {
		if err := service.VerifyPassword(ctx, password, hash); err != nil {
			t.Errorf("hash %d should verify password, got error: %v", i, err)
		}
	}
}

func TestBcryptService_DifferentCosts(t *testing.T) {
	ctx := context.Background()
	password := "testpassword123"

	costs := []int{4, 8, 10, 12, 14}

	for _, cost := range costs {
		t.Run(fmt.Sprintf("cost_%d", cost), func(t *testing.T) {
			cfg := config.BcryptConfig{Cost: cost}
			service := NewBcryptService(cfg)

			hash, err := service.HashPassword(ctx, password)
			if err != nil {
				t.Fatalf("failed to hash password with cost %d: %v", cost, err)
			}

			// Verify the hash contains the correct cost
			expectedPrefix := fmt.Sprintf("$2a$%02d$", cost)
			if !strings.HasPrefix(hash, expectedPrefix) {
				t.Errorf("hash should start with %s, got: %s", expectedPrefix, hash)
			}

			// Verify password
			if err := service.VerifyPassword(ctx, password, hash); err != nil {
				t.Errorf("failed to verify password with cost %d: %v", cost, err)
			}
		})
	}
}

func BenchmarkBcryptService_HashPassword(b *testing.B) {
	cfg := config.BcryptConfig{
		Cost: 12,
	}
	service := NewBcryptService(cfg)
	ctx := context.Background()
	password := "benchmarkpassword123"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := service.HashPassword(ctx, password)
		if err != nil {
			b.Fatalf("failed to hash password: %v", err)
		}
	}
}

func BenchmarkBcryptService_VerifyPassword(b *testing.B) {
	cfg := config.BcryptConfig{
		Cost: 12,
	}
	service := NewBcryptService(cfg)
	ctx := context.Background()
	password := "benchmarkpassword123"

	hash, err := service.HashPassword(ctx, password)
	if err != nil {
		b.Fatalf("failed to hash password: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := service.VerifyPassword(ctx, password, hash)
		if err != nil {
			b.Fatalf("failed to verify password: %v", err)
		}
	}
}

// Test different bcrypt costs performance
func BenchmarkBcryptService_DifferentCosts(b *testing.B) {
	ctx := context.Background()
	password := "benchmarkpassword123"
	costs := []int{4, 8, 10, 12, 14}

	for _, cost := range costs {
		b.Run(fmt.Sprintf("cost_%d", cost), func(b *testing.B) {
			cfg := config.BcryptConfig{Cost: cost}
			service := NewBcryptService(cfg)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := service.HashPassword(ctx, password)
				if err != nil {
					b.Fatalf("failed to hash password: %v", err)
				}
			}
		})
	}
}
