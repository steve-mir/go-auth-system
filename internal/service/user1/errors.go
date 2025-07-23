package user1

import (
	"fmt"

	"github.com/steve-mir/go-auth-system/internal/errors"
)

// User service specific error codes
const (
	ErrCodeUserNotFound         = "USER_NOT_FOUND"
	ErrCodeUserAlreadyExists    = "USER_ALREADY_EXISTS"
	ErrCodeInvalidPassword      = "INVALID_PASSWORD"
	ErrCodeUserLocked           = "USER_LOCKED"
	ErrCodeInvalidInput         = "INVALID_INPUT"
	ErrCodeEncryptionFailed     = "ENCRYPTION_FAILED"
	ErrCodeDecryptionFailed     = "DECRYPTION_FAILED"
	ErrCodeDatabaseError        = "DATABASE_ERROR"
	ErrCodeUnauthorized         = "UNAUTHORIZED"
	ErrCodePasswordTooWeak      = "PASSWORD_TOO_WEAK"
	ErrCodeEmailAlreadyInUse    = "EMAIL_ALREADY_IN_USE"
	ErrCodeUsernameAlreadyInUse = "USERNAME_ALREADY_IN_USE"
)

// NewUserNotFoundError creates a user not found error
func NewUserNotFoundError(userID string) *errors.AppError {
	return &errors.AppError{
		Type:    errors.ErrorTypeNotFound,
		Code:    ErrCodeUserNotFound,
		Message: fmt.Sprintf("User with ID %s not found", userID),
		Details: map[string]interface{}{
			"user_id": userID,
		},
	}
}

// NewUserAlreadyExistsError creates a user already exists error
func NewUserAlreadyExistsError(field, value string) *errors.AppError {
	return &errors.AppError{
		Type:    errors.ErrorTypeConflict,
		Code:    ErrCodeUserAlreadyExists,
		Message: fmt.Sprintf("User with %s '%s' already exists", field, value),
		Details: map[string]interface{}{
			"field": field,
			"value": value,
		},
	}
}

// NewInvalidPasswordError creates an invalid password error
func NewInvalidPasswordError() *errors.AppError {
	return &errors.AppError{
		Type:    errors.ErrorTypeAuthentication,
		Code:    ErrCodeInvalidPassword,
		Message: "Current password is incorrect",
	}
}

// NewUserLockedError creates a user locked error
func NewUserLockedError(userID string) *errors.AppError {
	return &errors.AppError{
		Type:    errors.ErrorTypeAuthorization,
		Code:    ErrCodeUserLocked,
		Message: "User account is locked",
		Details: map[string]interface{}{
			"user_id": userID,
		},
	}
}

// NewInvalidInputError creates an invalid input error
func NewInvalidInputError(field, message string) *errors.AppError {
	return &errors.AppError{
		Type:    errors.ErrorTypeValidation,
		Code:    ErrCodeInvalidInput,
		Message: fmt.Sprintf("Invalid %s: %s", field, message),
		Details: map[string]interface{}{
			"field": field,
		},
	}
}

// NewEncryptionError creates an encryption error
func NewEncryptionError(err error) *errors.AppError {
	return &errors.AppError{
		Type:    errors.ErrorTypeInternal,
		Code:    ErrCodeEncryptionFailed,
		Message: "Failed to encrypt sensitive data",
		Details: map[string]interface{}{
			"error": err.Error(),
		},
	}
}

// NewDecryptionError creates a decryption error
func NewDecryptionError(err error) *errors.AppError {
	return &errors.AppError{
		Type:    errors.ErrorTypeInternal,
		Code:    ErrCodeDecryptionFailed,
		Message: "Failed to decrypt sensitive data",
		Details: map[string]interface{}{
			"error": err.Error(),
		},
	}
}

// NewDatabaseError creates a database error
func NewDatabaseError(operation string, err error) *errors.AppError {
	return &errors.AppError{
		Type:    errors.ErrorTypeInternal,
		Code:    ErrCodeDatabaseError,
		Message: fmt.Sprintf("Database operation failed: %s", operation),
		Details: map[string]interface{}{
			"operation": operation,
			"error":     err.Error(),
		},
	}
}

// NewUnauthorizedError creates an unauthorized error
func NewUnauthorizedError(message string) *errors.AppError {
	return &errors.AppError{
		Type:    errors.ErrorTypeAuthorization,
		Code:    ErrCodeUnauthorized,
		Message: message,
	}
}

// NewPasswordTooWeakError creates a password too weak error
func NewPasswordTooWeakError(requirements string) *errors.AppError {
	return &errors.AppError{
		Type:    errors.ErrorTypeValidation,
		Code:    ErrCodePasswordTooWeak,
		Message: "Password does not meet security requirements",
		Details: map[string]interface{}{
			"requirements": requirements,
		},
	}
}

// NewEmailAlreadyInUseError creates an email already in use error
func NewEmailAlreadyInUseError(email string) *errors.AppError {
	return &errors.AppError{
		Type:    errors.ErrorTypeConflict,
		Code:    ErrCodeEmailAlreadyInUse,
		Message: "Email address is already in use",
		Details: map[string]interface{}{
			"email": email,
		},
	}
}

// NewUsernameAlreadyInUseError creates a username already in use error
func NewUsernameAlreadyInUseError(username string) *errors.AppError {
	return &errors.AppError{
		Type:    errors.ErrorTypeConflict,
		Code:    ErrCodeUsernameAlreadyInUse,
		Message: "Username is already in use",
		Details: map[string]interface{}{
			"username": username,
		},
	}
}
