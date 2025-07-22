package hash

import "context"

// HashService defines the interface for password hashing operations
type HashService interface {
	// HashPassword hashes a plain text password and returns the hash
	HashPassword(ctx context.Context, password string) (string, error)

	// VerifyPassword verifies a plain text password against a hash
	VerifyPassword(ctx context.Context, password, hash string) error

	// NeedsRehash checks if a hash needs to be rehashed due to changed parameters
	NeedsRehash(ctx context.Context, hash string) bool
}

// HashType represents the type of hashing algorithm
type HashType string

const (
	// HashTypeArgon2 represents Argon2id hashing
	HashTypeArgon2 HashType = "argon2"

	// HashTypeBcrypt represents bcrypt hashing
	HashTypeBcrypt HashType = "bcrypt"
)

// HashInfo contains metadata about a hash
type HashInfo struct {
	Type       HashType
	Version    string
	Parameters map[string]interface{}
}

// ParseHashInfo extracts hash information from a hash string
func ParseHashInfo(hash string) (*HashInfo, error) {
	if len(hash) == 0 {
		return nil, ErrInvalidHash
	}

	// Determine hash type based on prefix
	if hash[0] == '$' {
		// bcrypt format: $2a$cost$salt+hash
		if len(hash) >= 4 && hash[1:3] == "2a" || hash[1:3] == "2b" || hash[1:3] == "2y" {
			return &HashInfo{
				Type:    HashTypeBcrypt,
				Version: hash[1:3],
			}, nil
		}
	} else if hash[0:7] == "$argon2" {
		// Argon2 format: $argon2id$v=19$m=memory,t=iterations,p=parallelism$salt$hash
		return &HashInfo{
			Type:    HashTypeArgon2,
			Version: "19",
		}, nil
	}

	return nil, ErrUnsupportedHashFormat
}
