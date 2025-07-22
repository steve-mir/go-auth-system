package token

import (
	"errors"
	"fmt"
)

// Common token errors
var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrExpiredToken     = errors.New("token has expired")
	ErrRevokedToken     = errors.New("token has been revoked")
	ErrInvalidClaims    = errors.New("invalid token claims")
	ErrInvalidSignature = errors.New("invalid token signature")
	ErrInvalidFormat    = errors.New("invalid token format")
	ErrTokenNotFound    = errors.New("token not found")
	ErrInvalidTokenType = errors.New("invalid token type")
	ErrInvalidIssuer    = errors.New("invalid token issuer")
	ErrInvalidAudience  = errors.New("invalid token audience")
	ErrInvalidSubject   = errors.New("invalid token subject")
	ErrTokenGeneration  = errors.New("token generation failed")
	ErrKeyNotFound      = errors.New("signing key not found")
	ErrInvalidKey       = errors.New("invalid signing key")
)

// TokenError represents a token-related error with additional context
type TokenError struct {
	Type    string
	Message string
	Cause   error
}

// Error implements the error interface
func (e *TokenError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Type, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

// Unwrap returns the underlying error
func (e *TokenError) Unwrap() error {
	return e.Cause
}

// NewTokenError creates a new token error
func NewTokenError(errorType, message string, cause error) *TokenError {
	return &TokenError{
		Type:    errorType,
		Message: message,
		Cause:   cause,
	}
}

// Validation error types
const (
	ErrorTypeValidation   = "validation_error"
	ErrorTypeExpired      = "expired_error"
	ErrorTypeRevoked      = "revoked_error"
	ErrorTypeSignature    = "signature_error"
	ErrorTypeFormat       = "format_error"
	ErrorTypeGeneration   = "generation_error"
	ErrorTypeNotFound     = "not_found_error"
	ErrorTypeInvalidKey   = "invalid_key_error"
	ErrorTypeInvalidType  = "invalid_type_error"
	ErrorTypeInvalidClaim = "invalid_claim_error"
)

// Helper functions for creating specific error types
func NewValidationError(message string, cause error) *TokenError {
	return NewTokenError(ErrorTypeValidation, message, cause)
}

func NewExpiredError(message string, cause error) *TokenError {
	return NewTokenError(ErrorTypeExpired, message, cause)
}

func NewRevokedError(message string, cause error) *TokenError {
	return NewTokenError(ErrorTypeRevoked, message, cause)
}

func NewSignatureError(message string, cause error) *TokenError {
	return NewTokenError(ErrorTypeSignature, message, cause)
}

func NewFormatError(message string, cause error) *TokenError {
	return NewTokenError(ErrorTypeFormat, message, cause)
}

func NewGenerationError(message string, cause error) *TokenError {
	return NewTokenError(ErrorTypeGeneration, message, cause)
}

func NewNotFoundError(message string, cause error) *TokenError {
	return NewTokenError(ErrorTypeNotFound, message, cause)
}

func NewInvalidKeyError(message string, cause error) *TokenError {
	return NewTokenError(ErrorTypeInvalidKey, message, cause)
}

func NewInvalidTypeError(message string, cause error) *TokenError {
	return NewTokenError(ErrorTypeInvalidType, message, cause)
}

func NewInvalidClaimError(message string, cause error) *TokenError {
	return NewTokenError(ErrorTypeInvalidClaim, message, cause)
}
