package errors

import (
	"fmt"
	"net/http"
	"time"

	"google.golang.org/grpc/codes"
)

// ErrorType represents the category of error
type ErrorType string

const (
	ErrorTypeValidation     ErrorType = "validation"
	ErrorTypeAuthentication ErrorType = "authentication"
	ErrorTypeAuthorization  ErrorType = "authorization"
	ErrorTypeNotFound       ErrorType = "not_found"
	ErrorTypeConflict       ErrorType = "conflict"
	ErrorTypeRateLimit      ErrorType = "rate_limit"
	ErrorTypeInternal       ErrorType = "internal"
	ErrorTypeExternal       ErrorType = "external"
	ErrorTypeTimeout        ErrorType = "timeout"
	ErrorTypeUnavailable    ErrorType = "unavailable"
)

// AppError represents a structured application error
type AppError struct {
	Type      ErrorType   `json:"type"`
	Code      string      `json:"code"`
	Message   string      `json:"message"`
	Details   interface{} `json:"details,omitempty"`
	Cause     error       `json:"-"`
	Timestamp time.Time   `json:"timestamp"`
	TraceID   string      `json:"trace_id,omitempty"`
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (caused by: %v)", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying cause
func (e *AppError) Unwrap() error {
	return e.Cause
}

// Is checks if the error matches the target
func (e *AppError) Is(target error) bool {
	if t, ok := target.(*AppError); ok {
		return e.Code == t.Code && e.Type == t.Type
	}
	return false
}

// WithCause adds a cause to the error
func (e *AppError) WithCause(cause error) *AppError {
	e.Cause = cause
	return e
}

// WithDetails adds details to the error
func (e *AppError) WithDetails(details interface{}) *AppError {
	e.Details = details
	return e
}

// WithTraceID adds a trace ID to the error
func (e *AppError) WithTraceID(traceID string) *AppError {
	e.TraceID = traceID
	return e
}

// HTTPStatus returns the appropriate HTTP status code for the error
func (e *AppError) HTTPStatus() int {
	switch e.Type {
	case ErrorTypeValidation:
		return http.StatusBadRequest
	case ErrorTypeAuthentication:
		return http.StatusUnauthorized
	case ErrorTypeAuthorization:
		return http.StatusForbidden
	case ErrorTypeNotFound:
		return http.StatusNotFound
	case ErrorTypeConflict:
		return http.StatusConflict
	case ErrorTypeRateLimit:
		return http.StatusTooManyRequests
	case ErrorTypeTimeout:
		return http.StatusRequestTimeout
	case ErrorTypeUnavailable:
		return http.StatusServiceUnavailable
	case ErrorTypeExternal:
		return http.StatusBadGateway
	default:
		return http.StatusInternalServerError
	}
}

// GRPCCode returns the appropriate gRPC status code for the error
func (e *AppError) GRPCCode() codes.Code {
	switch e.Type {
	case ErrorTypeValidation:
		return codes.InvalidArgument
	case ErrorTypeAuthentication:
		return codes.Unauthenticated
	case ErrorTypeAuthorization:
		return codes.PermissionDenied
	case ErrorTypeNotFound:
		return codes.NotFound
	case ErrorTypeConflict:
		return codes.AlreadyExists
	case ErrorTypeRateLimit:
		return codes.ResourceExhausted
	case ErrorTypeTimeout:
		return codes.DeadlineExceeded
	case ErrorTypeUnavailable:
		return codes.Unavailable
	case ErrorTypeExternal:
		return codes.Unknown
	default:
		return codes.Internal
	}
}

// New creates a new AppError
func New(errorType ErrorType, code, message string) *AppError {
	return &AppError{
		Type:      errorType,
		Code:      code,
		Message:   message,
		Timestamp: time.Now(),
	}
}

// Newf creates a new AppError with formatted message
func Newf(errorType ErrorType, code, format string, args ...interface{}) *AppError {
	return &AppError{
		Type:      errorType,
		Code:      code,
		Message:   fmt.Sprintf(format, args...),
		Timestamp: time.Now(),
	}
}

// Wrap wraps an existing error as an AppError
func Wrap(err error, errorType ErrorType, code, message string) *AppError {
	return &AppError{
		Type:      errorType,
		Code:      code,
		Message:   message,
		Cause:     err,
		Timestamp: time.Now(),
	}
}

// Wrapf wraps an existing error as an AppError with formatted message
func Wrapf(err error, errorType ErrorType, code, format string, args ...interface{}) *AppError {
	return &AppError{
		Type:      errorType,
		Code:      code,
		Message:   fmt.Sprintf(format, args...),
		Cause:     err,
		Timestamp: time.Now(),
	}
}

// IsType checks if an error is of a specific type
func IsType(err error, errorType ErrorType) bool {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Type == errorType
	}
	return false
}

// GetType returns the error type if it's an AppError, otherwise returns ErrorTypeInternal
func GetType(err error) ErrorType {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Type
	}
	return ErrorTypeInternal
}

// GetCode returns the error code if it's an AppError, otherwise returns "UNKNOWN"
func GetCode(err error) string {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Code
	}
	return "UNKNOWN"
}

// ErrorResponse represents the structure of error responses
type ErrorResponse struct {
	Error     *AppError `json:"error"`
	RequestID string    `json:"request_id,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// NewErrorResponse creates a new error response
func NewErrorResponse(err *AppError, requestID string) *ErrorResponse {
	return &ErrorResponse{
		Error:     err,
		RequestID: requestID,
		Timestamp: time.Now(),
	}
}
