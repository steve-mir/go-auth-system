package config

import "fmt"

// Configuration validation errors
var (
	// Server errors
	ErrInvalidPort    = fmt.Errorf("invalid port number")
	ErrPortConflict   = fmt.Errorf("HTTP and gRPC ports cannot be the same")
	ErrMissingTLSCert = fmt.Errorf("TLS certificate file is required when TLS is enabled")
	ErrMissingTLSKey  = fmt.Errorf("TLS key file is required when TLS is enabled")

	// Database errors
	ErrMissingDBHost       = fmt.Errorf("database host is required")
	ErrMissingDBName       = fmt.Errorf("database name is required")
	ErrMissingDBUser       = fmt.Errorf("database user is required")
	ErrInvalidSSLMode      = fmt.Errorf("invalid SSL mode")
	ErrInvalidMaxOpenConns = fmt.Errorf("max open connections must be greater than 0")
	ErrInvalidMaxIdleConns = fmt.Errorf("max idle connections must be between 0 and max open connections")

	// Redis errors
	ErrMissingRedisHost    = fmt.Errorf("redis host is required")
	ErrInvalidRedisDB      = fmt.Errorf("redis database must be between 0 and 15")
	ErrInvalidPoolSize     = fmt.Errorf("pool size must be greater than 0")
	ErrInvalidMinIdleConns = fmt.Errorf("min idle connections must be between 0 and pool size")

	// Security errors
	ErrInvalidHashAlgorithm       = fmt.Errorf("invalid password hash algorithm")
	ErrInvalidArgon2Memory        = fmt.Errorf("argon2 memory must be at least 1024 KB")
	ErrInvalidArgon2Iterations    = fmt.Errorf("argon2 iterations must be at least 1")
	ErrInvalidArgon2Parallelism   = fmt.Errorf("argon2 parallelism must be at least 1")
	ErrInvalidArgon2SaltLength    = fmt.Errorf("argon2 salt length must be at least 8")
	ErrInvalidArgon2KeyLength     = fmt.Errorf("argon2 key length must be at least 16")
	ErrInvalidBcryptCost          = fmt.Errorf("bcrypt cost must be between 4 and 31")
	ErrInvalidTokenType           = fmt.Errorf("invalid token type")
	ErrInvalidAccessTTL           = fmt.Errorf("access token TTL must be positive")
	ErrInvalidRefreshTTL          = fmt.Errorf("refresh token TTL must be positive")
	ErrInvalidTTLRatio            = fmt.Errorf("refresh token TTL must be greater than access token TTL")
	ErrMissingSigningKey          = fmt.Errorf("token signing key is required")
	ErrMissingEncryptionKey       = fmt.Errorf("token encryption key is required for Paseto")
	ErrMissingIssuer              = fmt.Errorf("token issuer is required")
	ErrMissingAudience            = fmt.Errorf("token audience is required")
	ErrInvalidRequestsPerMin      = fmt.Errorf("requests per minute must be greater than 0")
	ErrInvalidBurstSize           = fmt.Errorf("burst size must be greater than 0")
	ErrInvalidWindowSize          = fmt.Errorf("window size must be positive")
	ErrInvalidCleanupPeriod       = fmt.Errorf("cleanup period must be positive")
	ErrInvalidEncryptionAlgorithm = fmt.Errorf("invalid encryption algorithm")
	ErrInvalidKeySize             = fmt.Errorf("key size must be at least 16")
	ErrMissingMasterKey           = fmt.Errorf("master encryption key is required")
	ErrInvalidKeyManagement       = fmt.Errorf("invalid key management type")

	// MFA errors
	ErrInvalidTOTPPeriod       = fmt.Errorf("TOTP period must be between 15 and 300 seconds")
	ErrInvalidTOTPDigits       = fmt.Errorf("TOTP digits must be between 6 and 8")
	ErrInvalidTOTPAlgorithm    = fmt.Errorf("invalid TOTP algorithm")
	ErrMissingSMSProvider      = fmt.Errorf("SMS provider is required when SMS MFA is enabled")
	ErrMissingSMSAPIKey        = fmt.Errorf("SMS API key is required when SMS MFA is enabled")
	ErrMissingEmailProvider    = fmt.Errorf("email provider is required when email MFA is enabled")
	ErrMissingEmailFrom        = fmt.Errorf("email from address is required when email MFA is enabled")
	ErrMissingWebAuthnRPID     = fmt.Errorf("WebAuthn RP ID is required when WebAuthn is enabled")
	ErrMissingWebAuthnRPOrigin = fmt.Errorf("WebAuthn RP origin is required when WebAuthn is enabled")
	ErrInvalidWebAuthnRPOrigin = fmt.Errorf("WebAuthn RP origin must be a valid URL")

	// SAML errors
	ErrMissingSAMLConfig = fmt.Errorf("SAML metadata URL or entity ID is required")
	ErrMissingSAMLACSURL = fmt.Errorf("SAML ACS URL is required")
	ErrInvalidSAMLACSURL = fmt.Errorf("SAML ACS URL must be a valid URL")

	// OIDC errors
	ErrMissingOIDCIssuer       = fmt.Errorf("OIDC issuer URL is required")
	ErrInvalidOIDCIssuer       = fmt.Errorf("OIDC issuer URL must be a valid URL")
	ErrMissingOIDCClientID     = fmt.Errorf("OIDC client ID is required")
	ErrMissingOIDCClientSecret = fmt.Errorf("OIDC client secret is required")

	// LDAP errors
	ErrMissingLDAPHost   = fmt.Errorf("LDAP host is required")
	ErrMissingLDAPBaseDN = fmt.Errorf("LDAP base DN is required")
)
