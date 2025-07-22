package hash

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/steve-mir/go-auth-system/internal/config"
)

// BcryptService implements HashService using bcrypt
type BcryptService struct {
	config config.BcryptConfig
}

// NewBcryptService creates a new bcrypt hash service
func NewBcryptService(cfg config.BcryptConfig) *BcryptService {
	return &BcryptService{
		config: cfg,
	}
}

// HashPassword hashes a password using bcrypt
func (s *BcryptService) HashPassword(ctx context.Context, password string) (string, error) {
	if err := validatePassword(password); err != nil {
		return "", err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.config.Cost)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrHashingFailed, err)
	}

	return string(hash), nil
}

// VerifyPassword verifies a password against a bcrypt hash
func (s *BcryptService) VerifyPassword(ctx context.Context, password, hash string) error {
	if err := validatePassword(password); err != nil {
		return err
	}

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return ErrHashMismatch
		}
		return fmt.Errorf("%w: %v", ErrInvalidHash, err)
	}

	return nil
}

// NeedsRehash checks if hash needs to be rehashed due to cost changes
func (s *BcryptService) NeedsRehash(ctx context.Context, hash string) bool {
	cost, err := s.getCostFromHash(hash)
	if err != nil {
		return true // Invalid hash should be rehashed
	}

	return cost != s.config.Cost
}

// getCostFromHash extracts the cost parameter from a bcrypt hash
func (s *BcryptService) getCostFromHash(hash string) (int, error) {
	if len(hash) < 7 {
		return 0, fmt.Errorf("hash too short")
	}

	// bcrypt hash format: $2a$cost$salt+hash
	// Extract the cost part
	parts := strings.Split(hash, "$")
	if len(parts) < 4 {
		return 0, fmt.Errorf("invalid bcrypt hash format")
	}

	// Validate bcrypt identifier
	if !strings.HasPrefix(parts[1], "2") {
		return 0, fmt.Errorf("not a bcrypt hash")
	}

	cost, err := strconv.Atoi(parts[2])
	if err != nil {
		return 0, fmt.Errorf("invalid cost parameter: %w", err)
	}

	return cost, nil
}
