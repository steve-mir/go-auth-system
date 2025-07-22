package audit

import (
	"errors"
	"fmt"
)

// Common audit service errors
var (
	ErrAuditLogNotFound    = errors.New("audit log not found")
	ErrInvalidPagination   = errors.New("invalid pagination parameters")
	ErrInvalidTimeRange    = errors.New("invalid time range")
	ErrMetadataMarshal     = errors.New("failed to marshal metadata")
	ErrMetadataUnmarshal   = errors.New("failed to unmarshal metadata")
	ErrDatabaseOperation   = errors.New("database operation failed")
	ErrInvalidUserID       = errors.New("invalid user ID")
	ErrInvalidAction       = errors.New("invalid action")
	ErrInvalidResourceType = errors.New("invalid resource type")
	ErrInvalidResourceID   = errors.New("invalid resource ID")
)

// AuditError represents an audit service specific error
type AuditError struct {
	Type    string
	Message string
	Err     error
}

// Error implements the error interface
func (e *AuditError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Type, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

// Unwrap returns the underlying error
func (e *AuditError) Unwrap() error {
	return e.Err
}

// NewAuditError creates a new audit error
func NewAuditError(errorType, message string, err error) *AuditError {
	return &AuditError{
		Type:    errorType,
		Message: message,
		Err:     err,
	}
}

// Error type constants
const (
	ErrorTypeValidation = "validation"
	ErrorTypeDatabase   = "database"
	ErrorTypeNotFound   = "not_found"
	ErrorTypeInternal   = "internal"
)

// Validation error helpers
func NewValidationError(message string, err error) *AuditError {
	return NewAuditError(ErrorTypeValidation, message, err)
}

func NewDatabaseError(message string, err error) *AuditError {
	return NewAuditError(ErrorTypeDatabase, message, err)
}

func NewNotFoundError(message string, err error) *AuditError {
	return NewAuditError(ErrorTypeNotFound, message, err)
}

func NewInternalError(message string, err error) *AuditError {
	return NewAuditError(ErrorTypeInternal, message, err)
}

// IsValidationError checks if the error is a validation error
func IsValidationError(err error) bool {
	var auditErr *AuditError
	if errors.As(err, &auditErr) {
		return auditErr.Type == ErrorTypeValidation
	}
	return false
}

// IsDatabaseError checks if the error is a database error
func IsDatabaseError(err error) bool {
	var auditErr *AuditError
	if errors.As(err, &auditErr) {
		return auditErr.Type == ErrorTypeDatabase
	}
	return false
}

// IsNotFoundError checks if the error is a not found error
func IsNotFoundError(err error) bool {
	var auditErr *AuditError
	if errors.As(err, &auditErr) {
		return auditErr.Type == ErrorTypeNotFound
	}
	return false
}

// IsInternalError checks if the error is an internal error
func IsInternalError(err error) bool {
	var auditErr *AuditError
	if errors.As(err, &auditErr) {
		return auditErr.Type == ErrorTypeInternal
	}
	return false
}
