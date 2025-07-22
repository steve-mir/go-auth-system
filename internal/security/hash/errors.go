package hash

import "errors"

var (
	// ErrInvalidPassword is returned when password validation fails
	ErrInvalidPassword = errors.New("invalid password")

	// ErrPasswordTooShort is returned when password is too short
	ErrPasswordTooShort = errors.New("password is too short")

	// ErrPasswordTooLong is returned when password is too long
	ErrPasswordTooLong = errors.New("password is too long")

	// ErrInvalidHash is returned when hash format is invalid
	ErrInvalidHash = errors.New("invalid hash format")

	// ErrUnsupportedHashFormat is returned when hash format is not supported
	ErrUnsupportedHashFormat = errors.New("unsupported hash format")

	// ErrHashMismatch is returned when password doesn't match hash
	ErrHashMismatch = errors.New("password does not match hash")

	// ErrInvalidSalt is returned when salt is invalid
	ErrInvalidSalt = errors.New("invalid salt")

	// ErrHashingFailed is returned when hashing operation fails
	ErrHashingFailed = errors.New("password hashing failed")
)

// Password validation constants
const (
	MinPasswordLength = 8
	MaxPasswordLength = 128
)
