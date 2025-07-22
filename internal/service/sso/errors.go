package sso

import (
	"fmt"

	"github.com/steve-mir/go-auth-system/internal/errors"
)

// SSO-specific error codes
const (
	ErrCodeProviderNotSupported  = "SSO_PROVIDER_NOT_SUPPORTED"
	ErrCodeInvalidState          = "SSO_INVALID_STATE"
	ErrCodeStateExpired          = "SSO_STATE_EXPIRED"
	ErrCodeOAuthExchangeFailed   = "SSO_OAUTH_EXCHANGE_FAILED"
	ErrCodeUserInfoFailed        = "SSO_USER_INFO_FAILED"
	ErrCodeAccountAlreadyLinked  = "SSO_ACCOUNT_ALREADY_LINKED"
	ErrCodeAccountNotLinked      = "SSO_ACCOUNT_NOT_LINKED"
	ErrCodeProviderNotConfigured = "SSO_PROVIDER_NOT_CONFIGURED"
	ErrCodeInvalidProvider       = "SSO_INVALID_PROVIDER"
	ErrCodeUserCreationFailed    = "SSO_USER_CREATION_FAILED"
	ErrCodeAccountLinkingFailed  = "SSO_ACCOUNT_LINKING_FAILED"

	// LDAP-specific error codes
	ErrCodeLDAPConnectionFailed     = "LDAP_CONNECTION_FAILED"
	ErrCodeLDAPBindFailed           = "LDAP_BIND_FAILED"
	ErrCodeLDAPUserNotFound         = "LDAP_USER_NOT_FOUND"
	ErrCodeLDAPUserDisabled         = "LDAP_USER_DISABLED"
	ErrCodeLDAPAuthenticationFailed = "LDAP_AUTHENTICATION_FAILED"
	ErrCodeLDAPSearchFailed         = "LDAP_SEARCH_FAILED"
	ErrCodeLDAPGroupSyncFailed      = "LDAP_GROUP_SYNC_FAILED"
	ErrCodeLDAPConfigInvalid        = "LDAP_CONFIG_INVALID"
)

// NewProviderNotSupportedError creates a new provider not supported error
func NewProviderNotSupportedError(provider string) *errors.AppError {
	return errors.New(
		errors.ErrorTypeValidation,
		ErrCodeProviderNotSupported,
		fmt.Sprintf("OAuth provider '%s' not supported", provider),
	)
}

// NewInvalidStateError creates a new invalid state error
func NewInvalidStateError() *errors.AppError {
	return errors.New(
		errors.ErrorTypeAuthentication,
		ErrCodeInvalidState,
		"Invalid OAuth state parameter",
	)
}

// NewStateExpiredError creates a new state expired error
func NewStateExpiredError() *errors.AppError {
	return errors.New(
		errors.ErrorTypeAuthentication,
		ErrCodeStateExpired,
		"OAuth state has expired",
	)
}

// NewOAuthExchangeFailedError creates a new OAuth exchange failed error
func NewOAuthExchangeFailedError(provider string, err error) *errors.AppError {
	return errors.New(
		errors.ErrorTypeExternal,
		ErrCodeOAuthExchangeFailed,
		fmt.Sprintf("Failed to exchange OAuth code for token with %s: %v", provider, err),
	)
}

// NewUserInfoFailedError creates a new user info failed error
func NewUserInfoFailedError(provider string, err error) *errors.AppError {
	return errors.New(
		errors.ErrorTypeExternal,
		ErrCodeUserInfoFailed,
		fmt.Sprintf("Failed to retrieve user information from %s: %v", provider, err),
	)
}

// NewAccountAlreadyLinkedError creates a new account already linked error
func NewAccountAlreadyLinkedError(provider string) *errors.AppError {
	return errors.New(
		errors.ErrorTypeConflict,
		ErrCodeAccountAlreadyLinked,
		fmt.Sprintf("Social account from %s is already linked to another user", provider),
	)
}

// NewAccountNotLinkedError creates a new account not linked error
func NewAccountNotLinkedError(provider string) *errors.AppError {
	return errors.New(
		errors.ErrorTypeNotFound,
		ErrCodeAccountNotLinked,
		fmt.Sprintf("Social account from %s is not linked to this user", provider),
	)
}

// NewProviderNotConfiguredError creates a new provider not configured error
func NewProviderNotConfiguredError(provider string) *errors.AppError {
	return errors.New(
		errors.ErrorTypeValidation,
		ErrCodeProviderNotConfigured,
		fmt.Sprintf("OAuth provider %s is not configured", provider),
	)
}

// NewInvalidProviderError creates a new invalid provider error
func NewInvalidProviderError(provider string) *errors.AppError {
	return errors.New(
		errors.ErrorTypeValidation,
		ErrCodeInvalidProvider,
		fmt.Sprintf("Invalid OAuth provider '%s'. Valid providers: google, facebook, github", provider),
	)
}

// NewUserCreationFailedError creates a new user creation failed error
func NewUserCreationFailedError(err error) *errors.AppError {
	return errors.New(
		errors.ErrorTypeInternal,
		ErrCodeUserCreationFailed,
		fmt.Sprintf("Failed to create user from social authentication: %v", err),
	)
}

// NewAccountLinkingFailedError creates a new account linking failed error
func NewAccountLinkingFailedError(err error) *errors.AppError {
	return errors.New(
		errors.ErrorTypeInternal,
		ErrCodeAccountLinkingFailed,
		fmt.Sprintf("Failed to link social account: %v", err),
	)
}

// LDAP-specific error functions

// NewLDAPConnectionFailedError creates a new LDAP connection failed error
func NewLDAPConnectionFailedError(host string, err error) *errors.AppError {
	return errors.New(
		errors.ErrorTypeExternal,
		ErrCodeLDAPConnectionFailed,
		fmt.Sprintf("Failed to connect to LDAP server %s: %v", host, err),
	)
}

// NewLDAPBindFailedError creates a new LDAP bind failed error
func NewLDAPBindFailedError(err error) *errors.AppError {
	return errors.New(
		errors.ErrorTypeAuthentication,
		ErrCodeLDAPBindFailed,
		fmt.Sprintf("LDAP bind failed: %v", err),
	)
}

// NewLDAPUserNotFoundError creates a new LDAP user not found error
func NewLDAPUserNotFoundError(username string) *errors.AppError {
	return errors.New(
		errors.ErrorTypeNotFound,
		ErrCodeLDAPUserNotFound,
		fmt.Sprintf("LDAP user '%s' not found", username),
	)
}

// NewLDAPUserDisabledError creates a new LDAP user disabled error
func NewLDAPUserDisabledError(username string) *errors.AppError {
	return errors.New(
		errors.ErrorTypeAuthentication,
		ErrCodeLDAPUserDisabled,
		fmt.Sprintf("LDAP user '%s' is disabled", username),
	)
}

// NewLDAPAuthenticationFailedError creates a new LDAP authentication failed error
func NewLDAPAuthenticationFailedError(username string, err error) *errors.AppError {
	return errors.New(
		errors.ErrorTypeAuthentication,
		ErrCodeLDAPAuthenticationFailed,
		fmt.Sprintf("LDAP authentication failed for user '%s': %v", username, err),
	)
}

// NewLDAPSearchFailedError creates a new LDAP search failed error
func NewLDAPSearchFailedError(err error) *errors.AppError {
	return errors.New(
		errors.ErrorTypeExternal,
		ErrCodeLDAPSearchFailed,
		fmt.Sprintf("LDAP search failed: %v", err),
	)
}

// NewLDAPGroupSyncFailedError creates a new LDAP group sync failed error
func NewLDAPGroupSyncFailedError(username string, err error) *errors.AppError {
	return errors.New(
		errors.ErrorTypeExternal,
		ErrCodeLDAPGroupSyncFailed,
		fmt.Sprintf("LDAP group synchronization failed for user '%s': %v", username, err),
	)
}

// NewLDAPConfigInvalidError creates a new LDAP config invalid error
func NewLDAPConfigInvalidError(message string) *errors.AppError {
	return errors.New(
		errors.ErrorTypeValidation,
		ErrCodeLDAPConfigInvalid,
		fmt.Sprintf("LDAP configuration invalid: %s", message),
	)
}

// Helper function to create LDAP error types for use in other files
type LDAPAuthenticationFailedError struct {
	*errors.AppError
}

func (e *LDAPAuthenticationFailedError) Error() string {
	return e.AppError.Message
}
