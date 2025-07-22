package hash

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/steve-mir/go-auth-system/internal/config"
)

// Argon2Service implements HashService using Argon2id
type Argon2Service struct {
	config config.Argon2Config
}

// NewArgon2Service creates a new Argon2 hash service
func NewArgon2Service(cfg config.Argon2Config) *Argon2Service {
	return &Argon2Service{
		config: cfg,
	}
}

// HashPassword hashes a password using Argon2id
func (s *Argon2Service) HashPassword(ctx context.Context, password string) (string, error) {
	if err := validatePassword(password); err != nil {
		return "", err
	}

	// Generate random salt
	salt := make([]byte, s.config.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("%w: failed to generate salt", ErrHashingFailed)
	}

	// Hash password using Argon2id
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		s.config.Iterations,
		s.config.Memory,
		s.config.Parallelism,
		s.config.KeyLength,
	)

	// Encode hash in PHC format
	encodedHash := s.encodeHash(hash, salt)
	return encodedHash, nil
}

// VerifyPassword verifies a password against an Argon2 hash
func (s *Argon2Service) VerifyPassword(ctx context.Context, password, encodedHash string) error {
	if err := validatePassword(password); err != nil {
		return err
	}

	// Parse the encoded hash
	params, salt, hash, err := s.decodeHash(encodedHash)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidHash, err)
	}

	// Hash the password with the same parameters
	computedHash := argon2.IDKey(
		[]byte(password),
		salt,
		params.iterations,
		params.memory,
		params.parallelism,
		uint32(len(hash)),
	)

	// Compare hashes using constant-time comparison
	if subtle.ConstantTimeCompare(hash, computedHash) == 1 {
		return nil
	}

	return ErrHashMismatch
}

// NeedsRehash checks if hash needs to be rehashed due to parameter changes
func (s *Argon2Service) NeedsRehash(ctx context.Context, encodedHash string) bool {
	params, _, _, err := s.decodeHash(encodedHash)
	if err != nil {
		return true // Invalid hash should be rehashed
	}

	// Check if any parameters have changed
	return params.memory != s.config.Memory ||
		params.iterations != s.config.Iterations ||
		params.parallelism != s.config.Parallelism ||
		params.keyLength != s.config.KeyLength
}

// argon2Params holds Argon2 parameters extracted from hash
type argon2Params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	keyLength   uint32
}

// encodeHash encodes hash and salt in PHC format
// Format: $argon2id$v=19$m=memory,t=iterations,p=parallelism$salt$hash
func (s *Argon2Service) encodeHash(hash, salt []byte) string {
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		s.config.Memory,
		s.config.Iterations,
		s.config.Parallelism,
		b64Salt,
		b64Hash,
	)
}

// decodeHash parses an Argon2 hash in PHC format
func (s *Argon2Service) decodeHash(encodedHash string) (*argon2Params, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return nil, nil, nil, fmt.Errorf("invalid hash format: expected 6 parts, got %d", len(parts))
	}

	if parts[1] != "argon2id" {
		return nil, nil, nil, fmt.Errorf("unsupported variant: %s", parts[1])
	}

	if parts[2] != "v=19" {
		return nil, nil, nil, fmt.Errorf("unsupported version: %s", parts[2])
	}

	// Parse parameters
	params, err := s.parseParams(parts[3])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse parameters: %w", err)
	}

	// Decode salt
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	// Decode hash
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode hash: %w", err)
	}

	params.keyLength = uint32(len(hash))

	return params, salt, hash, nil
}

// parseParams parses Argon2 parameters from string format
// Format: m=memory,t=iterations,p=parallelism
func (s *Argon2Service) parseParams(paramStr string) (*argon2Params, error) {
	params := &argon2Params{}

	paramPairs := strings.Split(paramStr, ",")
	for _, pair := range paramPairs {
		kv := strings.Split(pair, "=")
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid parameter format: %s", pair)
		}

		key, valueStr := kv[0], kv[1]
		value, err := strconv.ParseUint(valueStr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid parameter value for %s: %s", key, valueStr)
		}

		switch key {
		case "m":
			params.memory = uint32(value)
		case "t":
			params.iterations = uint32(value)
		case "p":
			params.parallelism = uint8(value)
		default:
			return nil, fmt.Errorf("unknown parameter: %s", key)
		}
	}

	return params, nil
}

// validatePassword validates password requirements
func validatePassword(password string) error {
	if len(password) < MinPasswordLength {
		return ErrPasswordTooShort
	}
	if len(password) > MaxPasswordLength {
		return ErrPasswordTooLong
	}
	return nil
}
