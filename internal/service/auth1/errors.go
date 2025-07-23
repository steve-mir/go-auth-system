package auth1

import "github.com/steve-mir/go-auth-system/internal/errors"

// Authentication error codes
const (
	ErrCodeInvalidCredentials    = "AUTH_INVALID_CREDENTIALS"
	ErrCodeUserNotFound          = "AUTH_USER_NOT_FOUND"
	ErrCodeUserAlreadyExists     = "AUTH_USER_ALREADY_EXISTS"
	ErrCodeAccountLocked         = "AUTH_ACCOUNT_LOCKED"
	ErrCodeEmailNotVerified      = "AUTH_EMAIL_NOT_VERIFIED"
	ErrCodeInvalidToken          = "AUTH_INVALID_TOKEN"
	ErrCodeTokenExpired          = "AUTH_TOKEN_EXPIRED"
	ErrCodeTokenRevoked          = "AUTH_TOKEN_REVOKED"
	ErrCodeInvalidRefreshToken   = "AUTH_INVALID_REFRESH_TOKEN"
	ErrCodePasswordTooWeak       = "AUTH_PASSWORD_TOO_WEAK"
	ErrCodeInvalidEmail          = "AUTH_INVALID_EMAIL"
	ErrCodeInvalidUsername       = "AUTH_INVALID_USERNAME"
	ErrCodeRegistrationDisabled  = "AUTH_REGISTRATION_DISABLED"
	ErrCodeTooManyAttempts       = "AUTH_TOO_MANY_ATTEMPTS"
	ErrCodeSessionNotFound       = "AUTH_SESSION_NOT_FOUND"
	ErrCodeSessionExpired        = "AUTH_SESSION_EXPIRED"
	ErrCodeInvalidLoginRequest   = "AUTH_INVALID_LOGIN_REQUEST"
	ErrCodeHashingFailed         = "AUTH_HASHING_FAILED"
	ErrCodeTokenGenerationFailed = "AUTH_TOKEN_GENERATION_FAILED"
)

// Predefined authentication errors
var (
	ErrInvalidCredentials = errors.New(
		errors.ErrorTypeAuthentication,
		ErrCodeInvalidCredentials,
		"Invalid email/username or password",
	)

	ErrUserNotFound = errors.New(
		errors.ErrorTypeNotFound,
		ErrCodeUserNotFound,
		"User not found",
	)

	ErrUserAlreadyExists = errors.New(
		errors.ErrorTypeConflict,
		ErrCodeUserAlreadyExists,
		"User with this email or username already exists",
	)

	ErrAccountLocked = errors.New(
		errors.ErrorTypeAuthentication,
		ErrCodeAccountLocked,
		"Account is locked due to too many failed login attempts",
	)

	ErrEmailNotVerified = errors.New(
		errors.ErrorTypeAuthentication,
		ErrCodeEmailNotVerified,
		"Email address is not verified",
	)

	ErrInvalidToken = errors.New(
		errors.ErrorTypeAuthentication,
		ErrCodeInvalidToken,
		"Invalid or malformed token",
	)

	ErrTokenExpired = errors.New(
		errors.ErrorTypeAuthentication,
		ErrCodeTokenExpired,
		"Token has expired",
	)

	ErrTokenRevoked = errors.New(
		errors.ErrorTypeAuthentication,
		ErrCodeTokenRevoked,
		"Token has been revoked",
	)

	ErrInvalidRefreshToken = errors.New(
		errors.ErrorTypeAuthentication,
		ErrCodeInvalidRefreshToken,
		"Invalid or expired refresh token",
	)

	ErrPasswordTooWeak = errors.New(
		errors.ErrorTypeValidation,
		ErrCodePasswordTooWeak,
		"Password does not meet security requirements",
	)

	ErrInvalidEmail = errors.New(
		errors.ErrorTypeValidation,
		ErrCodeInvalidEmail,
		"Invalid email address format",
	)

	ErrInvalidUsername = errors.New(
		errors.ErrorTypeValidation,
		ErrCodeInvalidUsername,
		"Invalid username format",
	)

	ErrRegistrationDisabled = errors.New(
		errors.ErrorTypeAuthorization,
		ErrCodeRegistrationDisabled,
		"User registration is currently disabled",
	)

	ErrTooManyAttempts = errors.New(
		errors.ErrorTypeRateLimit,
		ErrCodeTooManyAttempts,
		"Too many login attempts, please try again later",
	)

	ErrSessionNotFound = errors.New(
		errors.ErrorTypeNotFound,
		ErrCodeSessionNotFound,
		"Session not found or expired",
	)

	ErrSessionExpired = errors.New(
		errors.ErrorTypeAuthentication,
		ErrCodeSessionExpired,
		"Session has expired",
	)

	ErrInvalidLoginRequest = errors.New(
		errors.ErrorTypeValidation,
		ErrCodeInvalidLoginRequest,
		"Either email or username must be provided",
	)

	ErrHashingFailed = errors.New(
		errors.ErrorTypeInternal,
		ErrCodeHashingFailed,
		"Failed to hash password",
	)

	ErrTokenGenerationFailed = errors.New(
		errors.ErrorTypeInternal,
		ErrCodeTokenGenerationFailed,
		"Failed to generate authentication tokens",
	)
)
