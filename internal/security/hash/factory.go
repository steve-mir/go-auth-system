package hash

import (
	"fmt"

	"github.com/steve-mir/go-auth-system/internal/config"
)

// Factory creates HashService instances based on configuration
type Factory struct {
	config config.PasswordHashConfig
}

// NewFactory creates a new hash service factory
func NewFactory(cfg config.PasswordHashConfig) *Factory {
	return &Factory{
		config: cfg,
	}
}

// CreateHashService creates a HashService based on the configured algorithm
func (f *Factory) CreateHashService() (HashService, error) {
	switch f.config.Algorithm {
	case "argon2":
		return NewArgon2Service(f.config.Argon2), nil
	case "bcrypt":
		return NewBcryptService(f.config.Bcrypt), nil
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s", f.config.Algorithm)
	}
}

// GetAlgorithm returns the configured algorithm
func (f *Factory) GetAlgorithm() string {
	return f.config.Algorithm
}

// ValidateConfig validates the hash configuration
func (f *Factory) ValidateConfig() error {
	switch f.config.Algorithm {
	case "argon2":
		return f.validateArgon2Config()
	case "bcrypt":
		return f.validateBcryptConfig()
	default:
		return fmt.Errorf("unsupported hash algorithm: %s", f.config.Algorithm)
	}
}

// validateArgon2Config validates Argon2 configuration
func (f *Factory) validateArgon2Config() error {
	cfg := f.config.Argon2

	if cfg.Memory < 1024 {
		return fmt.Errorf("argon2 memory must be at least 1024 KB, got %d", cfg.Memory)
	}

	if cfg.Iterations < 1 {
		return fmt.Errorf("argon2 iterations must be at least 1, got %d", cfg.Iterations)
	}

	if cfg.Parallelism < 1 {
		return fmt.Errorf("argon2 parallelism must be at least 1, got %d", cfg.Parallelism)
	}

	if cfg.SaltLength < 8 {
		return fmt.Errorf("argon2 salt length must be at least 8, got %d", cfg.SaltLength)
	}

	if cfg.KeyLength < 16 {
		return fmt.Errorf("argon2 key length must be at least 16, got %d", cfg.KeyLength)
	}

	return nil
}

// validateBcryptConfig validates bcrypt configuration
func (f *Factory) validateBcryptConfig() error {
	cfg := f.config.Bcrypt

	if cfg.Cost < 4 || cfg.Cost > 31 {
		return fmt.Errorf("bcrypt cost must be between 4 and 31, got %d", cfg.Cost)
	}

	return nil
}

// GetRecommendedConfig returns recommended configuration for the algorithm
func (f *Factory) GetRecommendedConfig() config.PasswordHashConfig {
	switch f.config.Algorithm {
	case "argon2":
		return config.PasswordHashConfig{
			Algorithm: "argon2",
			Argon2: config.Argon2Config{
				Memory:      64 * 1024, // 64 MB
				Iterations:  3,
				Parallelism: 2,
				SaltLength:  16,
				KeyLength:   32,
			},
		}
	case "bcrypt":
		return config.PasswordHashConfig{
			Algorithm: "bcrypt",
			Bcrypt: config.BcryptConfig{
				Cost: 12,
			},
		}
	default:
		// Default to Argon2
		return config.PasswordHashConfig{
			Algorithm: "argon2",
			Argon2: config.Argon2Config{
				Memory:      64 * 1024,
				Iterations:  3,
				Parallelism: 2,
				SaltLength:  16,
				KeyLength:   32,
			},
		}
	}
}
