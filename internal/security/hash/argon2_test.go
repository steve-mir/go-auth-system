package hash

import (
	"context"
	"strings"
	"testing"

	"github.com/steve-mir/go-auth-system/internal/config"
)

func TestArgon2Service_HashPassword(t *testing.T) {
	cfg := config.Argon2Config{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
	service := NewArgon2Service(cfg)
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

			// Verify hash format
			if !strings.HasPrefix(hash, "$argon2id$v=19$") {
				t.Errorf("hash should start with $argon2id$v=19$, got: %s", hash)
			}

			// Verify hash contains expected parameters
			expectedParams := "m=65536,t=3,p=2"
			if !strings.Contains(hash, expectedParams) {
				t.Errorf("hash should contain parameters %s, got: %s", expectedParams, hash)
			}
		})
	}
}

func TestArgon2Service_VerifyPassword(t *testing.T) {
	cfg := config.Argon2Config{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
	service := NewArgon2Service(cfg)
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
			name:        "bcrypt hash",
			password:    password,
			hash:        "$2a$12$invalid",
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

func TestArgon2Service_NeedsRehash(t *testing.T) {
	cfg := config.Argon2Config{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
	service := NewArgon2Service(cfg)
	ctx := context.Background()

	password := "testpassword123"
	hash, err := service.HashPassword(ctx, password)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	tests := []struct {
		name           string
		hash           string
		newConfig      config.Argon2Config
		expectedRehash bool
	}{
		{
			name:           "same parameters",
			hash:           hash,
			newConfig:      cfg,
			expectedRehash: false,
		},
		{
			name: "different memory",
			hash: hash,
			newConfig: config.Argon2Config{
				Memory:      32 * 1024,
				Iterations:  3,
				Parallelism: 2,
				SaltLength:  16,
				KeyLength:   32,
			},
			expectedRehash: true,
		},
		{
			name: "different iterations",
			hash: hash,
			newConfig: config.Argon2Config{
				Memory:      64 * 1024,
				Iterations:  4,
				Parallelism: 2,
				SaltLength:  16,
				KeyLength:   32,
			},
			expectedRehash: true,
		},
		{
			name: "different parallelism",
			hash: hash,
			newConfig: config.Argon2Config{
				Memory:      64 * 1024,
				Iterations:  3,
				Parallelism: 4,
				SaltLength:  16,
				KeyLength:   32,
			},
			expectedRehash: true,
		},
		{
			name: "different key length",
			hash: hash,
			newConfig: config.Argon2Config{
				Memory:      64 * 1024,
				Iterations:  3,
				Parallelism: 2,
				SaltLength:  16,
				KeyLength:   64,
			},
			expectedRehash: true,
		},
		{
			name:           "invalid hash",
			hash:           "invalid_hash",
			newConfig:      cfg,
			expectedRehash: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newService := NewArgon2Service(tt.newConfig)
			needsRehash := newService.NeedsRehash(ctx, tt.hash)

			if needsRehash != tt.expectedRehash {
				t.Errorf("expected needsRehash=%v, got %v", tt.expectedRehash, needsRehash)
			}
		})
	}
}

func TestArgon2Service_HashConsistency(t *testing.T) {
	cfg := config.Argon2Config{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
	service := NewArgon2Service(cfg)
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

func BenchmarkArgon2Service_HashPassword(b *testing.B) {
	cfg := config.Argon2Config{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
	service := NewArgon2Service(cfg)
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

func BenchmarkArgon2Service_VerifyPassword(b *testing.B) {
	cfg := config.Argon2Config{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
	service := NewArgon2Service(cfg)
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
