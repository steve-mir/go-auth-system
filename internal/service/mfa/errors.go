package mfa

import "github.com/steve-mir/go-auth-system/internal/errors"

// MFA-specific errors
var (
	// General MFA errors
	ErrMFANotFound = errors.New(
		errors.ErrorTypeNotFound,
		"MFA_NOT_FOUND",
		"MFA configuration not found",
	)

	ErrMFAAlreadyExists = errors.New(
		errors.ErrorTypeConflict,
		"MFA_ALREADY_EXISTS",
		"MFA method already configured for this user",
	)

	ErrMFANotEnabled = errors.New(
		errors.ErrorTypeValidation,
		"MFA_NOT_ENABLED",
		"MFA method is not enabled",
	)

	ErrMFARequired = errors.New(
		errors.ErrorTypeAuthentication,
		"MFA_REQUIRED",
		"Multi-factor authentication is required",
	)

	ErrInvalidMFAMethod = errors.New(
		errors.ErrorTypeValidation,
		"INVALID_MFA_METHOD",
		"Invalid MFA method specified",
	)

	// TOTP-specific errors
	ErrInvalidTOTPCode = errors.New(
		errors.ErrorTypeAuthentication,
		"INVALID_TOTP_CODE",
		"Invalid TOTP code provided",
	)

	ErrTOTPSecretGeneration = errors.New(
		errors.ErrorTypeInternal,
		"TOTP_SECRET_GENERATION_FAILED",
		"Failed to generate TOTP secret",
	)

	ErrTOTPQRCodeGeneration = errors.New(
		errors.ErrorTypeInternal,
		"TOTP_QR_CODE_GENERATION_FAILED",
		"Failed to generate TOTP QR code",
	)

	ErrInvalidTOTPSetupToken = errors.New(
		errors.ErrorTypeAuthentication,
		"INVALID_TOTP_SETUP_TOKEN",
		"Invalid or expired TOTP setup token",
	)

	// SMS-specific errors
	ErrInvalidSMSCode = errors.New(
		errors.ErrorTypeAuthentication,
		"INVALID_SMS_CODE",
		"Invalid SMS verification code",
	)

	ErrSMSCodeExpired = errors.New(
		errors.ErrorTypeAuthentication,
		"SMS_CODE_EXPIRED",
		"SMS verification code has expired",
	)

	ErrSMSCodeNotFound = errors.New(
		errors.ErrorTypeNotFound,
		"SMS_CODE_NOT_FOUND",
		"SMS verification code not found",
	)

	ErrSMSSendFailed = errors.New(
		errors.ErrorTypeExternal,
		"SMS_SEND_FAILED",
		"Failed to send SMS verification code",
	)

	ErrInvalidPhoneNumber = errors.New(
		errors.ErrorTypeValidation,
		"INVALID_PHONE_NUMBER",
		"Invalid phone number format",
	)

	ErrPhoneNotVerified = errors.New(
		errors.ErrorTypeValidation,
		"PHONE_NOT_VERIFIED",
		"Phone number is not verified",
	)

	// Email-specific errors
	ErrInvalidEmailCode = errors.New(
		errors.ErrorTypeAuthentication,
		"INVALID_EMAIL_CODE",
		"Invalid email verification code",
	)

	ErrEmailCodeExpired = errors.New(
		errors.ErrorTypeAuthentication,
		"EMAIL_CODE_EXPIRED",
		"Email verification code has expired",
	)

	ErrEmailCodeNotFound = errors.New(
		errors.ErrorTypeNotFound,
		"EMAIL_CODE_NOT_FOUND",
		"Email verification code not found",
	)

	ErrEmailSendFailed = errors.New(
		errors.ErrorTypeExternal,
		"EMAIL_SEND_FAILED",
		"Failed to send email verification code",
	)

	ErrInvalidEmailAddress = errors.New(
		errors.ErrorTypeValidation,
		"INVALID_EMAIL_ADDRESS",
		"Invalid email address format",
	)

	ErrEmailNotVerified = errors.New(
		errors.ErrorTypeValidation,
		"EMAIL_NOT_VERIFIED",
		"Email address is not verified",
	)

	// Backup code errors
	ErrInvalidBackupCode = errors.New(
		errors.ErrorTypeAuthentication,
		"INVALID_BACKUP_CODE",
		"Invalid backup code provided",
	)

	ErrBackupCodeAlreadyUsed = errors.New(
		errors.ErrorTypeAuthentication,
		"BACKUP_CODE_ALREADY_USED",
		"Backup code has already been used",
	)

	ErrBackupCodeGenerationFailed = errors.New(
		errors.ErrorTypeInternal,
		"BACKUP_CODE_GENERATION_FAILED",
		"Failed to generate backup codes",
	)

	ErrNoBackupCodesAvailable = errors.New(
		errors.ErrorTypeValidation,
		"NO_BACKUP_CODES_AVAILABLE",
		"No backup codes available for this MFA method",
	)

	// User-related errors
	ErrUserNotFound = errors.New(
		errors.ErrorTypeNotFound,
		"USER_NOT_FOUND",
		"User not found",
	)

	ErrUserAccountLocked = errors.New(
		errors.ErrorTypeAuthentication,
		"USER_ACCOUNT_LOCKED",
		"User account is locked",
	)

	// Encryption/Decryption errors
	ErrEncryptionFailed = errors.New(
		errors.ErrorTypeInternal,
		"ENCRYPTION_FAILED",
		"Failed to encrypt sensitive data",
	)

	ErrDecryptionFailed = errors.New(
		errors.ErrorTypeInternal,
		"DECRYPTION_FAILED",
		"Failed to decrypt sensitive data",
	)

	// Cache errors
	ErrCacheOperationFailed = errors.New(
		errors.ErrorTypeInternal,
		"CACHE_OPERATION_FAILED",
		"Cache operation failed",
	)

	// Rate limiting errors
	ErrTooManyAttempts = errors.New(
		errors.ErrorTypeRateLimit,
		"TOO_MANY_ATTEMPTS",
		"Too many verification attempts, please try again later",
	)

	ErrCodeGenerationRateLimit = errors.New(
		errors.ErrorTypeRateLimit,
		"CODE_GENERATION_RATE_LIMIT",
		"Too many code generation requests, please wait before requesting another",
	)

	// Configuration errors
	ErrMFAConfigurationInvalid = errors.New(
		errors.ErrorTypeValidation,
		"MFA_CONFIGURATION_INVALID",
		"MFA configuration is invalid",
	)

	ErrMFASetupIncomplete = errors.New(
		errors.ErrorTypeValidation,
		"MFA_SETUP_INCOMPLETE",
		"MFA setup is not complete",
	)

	// WebAuthn-specific errors
	ErrWebAuthnChallengeGeneration = errors.New(
		errors.ErrorTypeInternal,
		"WEBAUTHN_CHALLENGE_GENERATION_FAILED",
		"Failed to generate WebAuthn challenge",
	)

	ErrWebAuthnCredentialCreation = errors.New(
		errors.ErrorTypeInternal,
		"WEBAUTHN_CREDENTIAL_CREATION_FAILED",
		"Failed to create WebAuthn credential",
	)

	ErrWebAuthnCredentialVerification = errors.New(
		errors.ErrorTypeAuthentication,
		"WEBAUTHN_CREDENTIAL_VERIFICATION_FAILED",
		"WebAuthn credential verification failed",
	)

	ErrWebAuthnInvalidCredential = errors.New(
		errors.ErrorTypeAuthentication,
		"WEBAUTHN_INVALID_CREDENTIAL",
		"Invalid WebAuthn credential",
	)

	ErrWebAuthnCredentialNotFound = errors.New(
		errors.ErrorTypeNotFound,
		"WEBAUTHN_CREDENTIAL_NOT_FOUND",
		"WebAuthn credential not found",
	)

	ErrWebAuthnSetupNotFound = errors.New(
		errors.ErrorTypeNotFound,
		"WEBAUTHN_SETUP_NOT_FOUND",
		"WebAuthn setup session not found or expired",
	)

	ErrWebAuthnLoginNotFound = errors.New(
		errors.ErrorTypeNotFound,
		"WEBAUTHN_LOGIN_NOT_FOUND",
		"WebAuthn login session not found or expired",
	)

	ErrWebAuthnInvalidChallenge = errors.New(
		errors.ErrorTypeAuthentication,
		"WEBAUTHN_INVALID_CHALLENGE",
		"Invalid WebAuthn challenge",
	)

	ErrWebAuthnInvalidOrigin = errors.New(
		errors.ErrorTypeAuthentication,
		"WEBAUTHN_INVALID_ORIGIN",
		"Invalid WebAuthn origin",
	)

	ErrWebAuthnInvalidClientData = errors.New(
		errors.ErrorTypeAuthentication,
		"WEBAUTHN_INVALID_CLIENT_DATA",
		"Invalid WebAuthn client data",
	)

	ErrWebAuthnInvalidAttestation = errors.New(
		errors.ErrorTypeAuthentication,
		"WEBAUTHN_INVALID_ATTESTATION",
		"Invalid WebAuthn attestation",
	)

	ErrWebAuthnInvalidAssertion = errors.New(
		errors.ErrorTypeAuthentication,
		"WEBAUTHN_INVALID_ASSERTION",
		"Invalid WebAuthn assertion",
	)

	ErrWebAuthnSignatureVerification = errors.New(
		errors.ErrorTypeAuthentication,
		"WEBAUTHN_SIGNATURE_VERIFICATION_FAILED",
		"WebAuthn signature verification failed",
	)

	ErrWebAuthnUnsupportedAlgorithm = errors.New(
		errors.ErrorTypeValidation,
		"WEBAUTHN_UNSUPPORTED_ALGORITHM",
		"Unsupported WebAuthn algorithm",
	)
)
