package hash

import (
	"context"
	"testing"

	"github.com/steve-mir/go-auth-system/internal/config"
)

func TestFactory_CreateHashService(t *testing.T) {
	tests := []struct {
		name        string
		config      config.PasswordHashConfig
		expectError bool
		serviceType string
	}{
		{
			name: "argon2 service",
			config: config.PasswordHashConfig{
				Algorithm: "argon2",
				Argon2: config.Argon2Config{
					Memory:      64 * 1024,
					Iterations:  3,
					Parallelism: 2,
					SaltLength:  16,
					KeyLength:   32,
				},
			},
			expectError: false,
			serviceType: "*hash.Argon2Service",
		},
		{
			name: "bcrypt service",
			config: config.PasswordHashConfig{
				Algorithm: "bcrypt",
				Bcrypt: config.BcryptConfig{
					Cost: 12,
				},
			},
			expectError: false,
			serviceType: "*hash.BcryptService",
		},
		{
			name: "unsupported algorithm",
			config: config.PasswordHashConfig{
				Algorithm: "md5",
			},
			expectError: true,
		},
		{
			name: "empty algorithm",
			config: config.PasswordHashConfig{
				Algorithm: "",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factory := NewFactory(tt.config)
			service, err := factory.CreateHashService()

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				if service != nil {
					t.Errorf("expected nil service but got %T", service)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if service == nil {
				t.Error("service should not be nil")
				return
			}

			// Test that the service works
			ctx := context.Background()
			password := "testpassword123"
			hash, err := service.HashPassword(ctx, password)
			if err != nil {
				t.Errorf("service should be able to hash password: %v", err)
				return
			}

			if err := service.VerifyPassword(ctx, password, hash); err != nil {
				t.Errorf("service should be able to verify password: %v", err)
			}
		})
	}
}

func TestFactory_GetAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
	}{
		{
			name:      "argon2",
			algorithm: "argon2",
		},
		{
			name:      "bcrypt",
			algorithm: "bcrypt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := config.PasswordHashConfig{
				Algorithm: tt.algorithm,
			}
			factory := NewFactory(config)

			if got := factory.GetAlgorithm(); got != tt.algorithm {
				t.Errorf("GetAlgorithm() = %v, want %v", got, tt.algorithm)
			}
		})
	}
}

func TestFactory_ValidateConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      config.PasswordHashConfig
		expectError bool
	}{
		{
			name: "valid argon2 config",
			config: config.PasswordHashConfig{
				Algorithm: "argon2",
				Argon2: config.Argon2Config{
					Memory:      64 * 1024,
					Iterations:  3,
					Parallelism: 2,
					SaltLength:  16,
					KeyLength:   32,
				},
			},
			expectError: false,
		},
		{
			name: "valid bcrypt config",
			config: config.PasswordHashConfig{
				Algorithm: "bcrypt",
				Bcrypt: config.BcryptConfig{
					Cost: 12,
				},
			},
			expectError: false,
		},
		{
			name: "invalid argon2 memory",
			config: config.PasswordHashConfig{
				Algorithm: "argon2",
				Argon2: config.Argon2Config{
					Memory:      512, // Too low
					Iterations:  3,
					Parallelism: 2,
					SaltLength:  16,
					KeyLength:   32,
				},
			},
			expectError: true,
		},
		{
			name: "invalid argon2 iterations",
			config: config.PasswordHashConfig{
				Algorithm: "argon2",
				Argon2: config.Argon2Config{
					Memory:      64 * 1024,
					Iterations:  0, // Too low
					Parallelism: 2,
					SaltLength:  16,
					KeyLength:   32,
				},
			},
			expectError: true,
		},
		{
			name: "invalid argon2 parallelism",
			config: config.PasswordHashConfig{
				Algorithm: "argon2",
				Argon2: config.Argon2Config{
					Memory:      64 * 1024,
					Iterations:  3,
					Parallelism: 0, // Too low
					SaltLength:  16,
					KeyLength:   32,
				},
			},
			expectError: true,
		},
		{
			name: "invalid argon2 salt length",
			config: config.PasswordHashConfig{
				Algorithm: "argon2",
				Argon2: config.Argon2Config{
					Memory:      64 * 1024,
					Iterations:  3,
					Parallelism: 2,
					SaltLength:  4, // Too low
					KeyLength:   32,
				},
			},
			expectError: true,
		},
		{
			name: "invalid argon2 key length",
			config: config.PasswordHashConfig{
				Algorithm: "argon2",
				Argon2: config.Argon2Config{
					Memory:      64 * 1024,
					Iterations:  3,
					Parallelism: 2,
					SaltLength:  16,
					KeyLength:   8, // Too low
				},
			},
			expectError: true,
		},
		{
			name: "invalid bcrypt cost too low",
			config: config.PasswordHashConfig{
				Algorithm: "bcrypt",
				Bcrypt: config.BcryptConfig{
					Cost: 3, // Too low
				},
			},
			expectError: true,
		},
		{
			name: "invalid bcrypt cost too high",
			config: config.PasswordHashConfig{
				Algorithm: "bcrypt",
				Bcrypt: config.BcryptConfig{
					Cost: 32, // Too high
				},
			},
			expectError: true,
		},
		{
			name: "unsupported algorithm",
			config: config.PasswordHashConfig{
				Algorithm: "sha256",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factory := NewFactory(tt.config)
			err := factory.ValidateConfig()

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestFactory_GetRecommendedConfig(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
	}{
		{
			name:      "argon2 recommended",
			algorithm: "argon2",
		},
		{
			name:      "bcrypt recommended",
			algorithm: "bcrypt",
		},
		{
			name:      "unknown algorithm defaults to argon2",
			algorithm: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := config.PasswordHashConfig{
				Algorithm: tt.algorithm,
			}
			factory := NewFactory(config)
			recommended := factory.GetRecommendedConfig()

			// Validate that recommended config is valid
			recommendedFactory := NewFactory(recommended)
			if err := recommendedFactory.ValidateConfig(); err != nil {
				t.Errorf("recommended config should be valid: %v", err)
			}

			// Test that recommended config can create a working service
			service, err := recommendedFactory.CreateHashService()
			if err != nil {
				t.Errorf("recommended config should create working service: %v", err)
				return
			}

			// Test the service
			ctx := context.Background()
			password := "testpassword123"
			hash, err := service.HashPassword(ctx, password)
			if err != nil {
				t.Errorf("recommended service should hash password: %v", err)
				return
			}

			if err := service.VerifyPassword(ctx, password, hash); err != nil {
				t.Errorf("recommended service should verify password: %v", err)
			}
		})
	}
}

func TestFactory_Integration(t *testing.T) {
	// Test complete workflow with both algorithms
	algorithms := []string{"argon2", "bcrypt"}

	for _, algorithm := range algorithms {
		t.Run(algorithm, func(t *testing.T) {
			// Get recommended config
			factory := NewFactory(config.PasswordHashConfig{Algorithm: algorithm})
			cfg := factory.GetRecommendedConfig()

			// Validate config
			newFactory := NewFactory(cfg)
			if err := newFactory.ValidateConfig(); err != nil {
				t.Fatalf("recommended config should be valid: %v", err)
			}

			// Create service
			service, err := newFactory.CreateHashService()
			if err != nil {
				t.Fatalf("should create service: %v", err)
			}

			// Test password operations
			ctx := context.Background()
			password := "integrationtest123"

			// Hash password
			hash, err := service.HashPassword(ctx, password)
			if err != nil {
				t.Fatalf("should hash password: %v", err)
			}

			// Verify correct password
			if err := service.VerifyPassword(ctx, password, hash); err != nil {
				t.Errorf("should verify correct password: %v", err)
			}

			// Verify incorrect password
			if err := service.VerifyPassword(ctx, "wrongpassword", hash); err == nil {
				t.Error("should not verify incorrect password")
			}

			// Check rehash (should not need rehash with same config)
			if service.NeedsRehash(ctx, hash) {
				t.Error("should not need rehash with same config")
			}
		})
	}
}
