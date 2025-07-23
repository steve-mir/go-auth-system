package config

import (
	"fmt"
	"net/url"
	"strings"
)

// validate validates the configuration
func validate(config *Config) error {
	if err := validateServer(&config.Server); err != nil {
		return fmt.Errorf("server config: %w", err)
	}

	if err := validateDatabase(&config.Database); err != nil {
		return fmt.Errorf("database config: %w", err)
	}

	if err := validateRedis(&config.Redis); err != nil {
		return fmt.Errorf("redis config: %w", err)
	}

	if err := validateSecurity(&config.Security); err != nil {
		return fmt.Errorf("security config: %w", err)
	}

	if err := validateFeatures(&config.Features); err != nil {
		return fmt.Errorf("features config: %w", err)
	}

	return nil
}

// validateServer validates server configuration
func validateServer(server *ServerConfig) error {
	if server.Port < 1 || server.Port > 65535 {
		return ErrInvalidPort
	}

	if server.GRPCPort < 1 || server.GRPCPort > 65535 {
		return ErrInvalidPort
	}

	if server.Port == server.GRPCPort {
		return ErrPortConflict
	}

	if server.TLS.Enabled {
		if server.TLS.CertFile == "" {
			return ErrMissingTLSCert
		}
		if server.TLS.KeyFile == "" {
			return ErrMissingTLSKey
		}
	}

	return nil
}

// validateDatabase validates database configuration
func validateDatabase(db *DatabaseConfig) error {
	if db.Host == "" {
		return ErrMissingDBHost
	}

	if db.Port < 1 || db.Port > 65535 {
		return ErrInvalidPort
	}

	if db.Name == "" {
		return ErrMissingDBName
	}

	if db.User == "" {
		return ErrMissingDBUser
	}

	validSSLModes := []string{"disable", "require", "verify-ca", "verify-full"}
	if !contains(validSSLModes, db.SSLMode) {
		return ErrInvalidSSLMode
	}

	if db.MaxOpenConns < 1 {
		return ErrInvalidMaxOpenConns
	}

	if db.MaxIdleConns < 0 || db.MaxIdleConns > db.MaxOpenConns {
		return ErrInvalidMaxIdleConns
	}

	return nil
}

// validateRedis validates Redis configuration
func validateRedis(redis *RedisConfig) error {
	if redis.Host == "" {
		return ErrMissingRedisHost
	}

	if redis.Port < 1 || redis.Port > 65535 {
		return ErrInvalidPort
	}

	if redis.DB < 0 || redis.DB > 15 {
		return ErrInvalidRedisDB
	}

	if redis.PoolSize < 1 {
		return ErrInvalidPoolSize
	}

	if redis.MinIdleConns < 0 || redis.MinIdleConns > redis.PoolSize {
		return ErrInvalidMinIdleConns
	}

	return nil
}

// validateSecurity validates security configuration
func validateSecurity(security *SecurityConfig) error {
	if err := validatePasswordHash(&security.PasswordHash); err != nil {
		return fmt.Errorf("password hash: %w", err)
	}

	if err := validateToken(&security.Token); err != nil {
		return fmt.Errorf("token: %w", err)
	}

	if err := validateRateLimit(&security.RateLimit); err != nil {
		return fmt.Errorf("rate limit: %w", err)
	}

	if err := validateEncryption(&security.Encryption); err != nil {
		return fmt.Errorf("encryption: %w", err)
	}

	return nil
}

// validatePasswordHash validates password hash configuration
func validatePasswordHash(hash *PasswordHashConfig) error {
	validAlgorithms := []string{"argon2", "bcrypt"}
	if !contains(validAlgorithms, hash.Algorithm) {
		return ErrInvalidHashAlgorithm
	}

	if hash.Algorithm == "argon2" {
		if hash.Argon2.Memory < 1024 {
			return ErrInvalidArgon2Memory
		}
		if hash.Argon2.Iterations < 1 {
			return ErrInvalidArgon2Iterations
		}
		if hash.Argon2.Parallelism < 1 {
			return ErrInvalidArgon2Parallelism
		}
		if hash.Argon2.SaltLength < 8 {
			return ErrInvalidArgon2SaltLength
		}
		if hash.Argon2.KeyLength < 16 {
			return ErrInvalidArgon2KeyLength
		}
	}

	if hash.Algorithm == "bcrypt" {
		if hash.Bcrypt.Cost < 4 || hash.Bcrypt.Cost > 31 {
			return ErrInvalidBcryptCost
		}
	}

	return nil
}

// validateToken validates token configuration
func validateToken(token *TokenConfig) error {
	validTypes := []string{"jwt", "paseto"}
	if !contains(validTypes, token.Type) {
		return ErrInvalidTokenType
	}

	if token.AccessTTL <= 0 {
		return ErrInvalidAccessTTL
	}

	if token.RefreshTTL <= 0 {
		return ErrInvalidRefreshTTL
	}

	if token.RefreshTTL <= token.AccessTTL {
		return ErrInvalidTTLRatio
	}

	if token.SigningKey == "" {
		return ErrMissingSigningKey
	}

	if token.Type == "paseto" && token.EncryptionKey == "" {
		return ErrMissingEncryptionKey
	}

	if token.Issuer == "" {
		return ErrMissingIssuer
	}

	if token.Audience == "" {
		return ErrMissingAudience
	}

	return nil
}

// validateRateLimit validates rate limit configuration
func validateRateLimit(rateLimit *RateLimitConfig) error {
	if rateLimit.Enabled {
		if rateLimit.RequestsPerMin < 1 {
			return ErrInvalidRequestsPerMin
		}
		if rateLimit.BurstSize < 1 {
			return ErrInvalidBurstSize
		}
		if rateLimit.WindowSize <= 0 {
			return ErrInvalidWindowSize
		}
		if rateLimit.CleanupPeriod <= 0 {
			return ErrInvalidCleanupPeriod
		}
	}
	return nil
}

// validateEncryption validates encryption configuration
func validateEncryption(encryption *EncryptionConfig) error {
	validAlgorithms := []string{"aes-256-gcm"}
	if !contains(validAlgorithms, encryption.Algorithm) {
		return ErrInvalidEncryptionAlgorithm
	}

	if encryption.KeySize < 16 {
		return ErrInvalidKeySize
	}

	if encryption.MasterKey == "" {
		return ErrMissingMasterKey
	}

	validKeyManagement := []string{"local", "vault"}
	if !contains(validKeyManagement, encryption.KeyManagement) {
		return ErrInvalidKeyManagement
	}

	return nil
}

// validateFeatures validates features configuration
func validateFeatures(features *FeaturesConfig) error {
	if err := validateMFA(&features.MFA); err != nil {
		return fmt.Errorf("mfa: %w", err)
	}

	if err := validateSocialAuth(&features.SocialAuth); err != nil {
		return fmt.Errorf("social auth: %w", err)
	}

	if err := validateEnterpriseSSO(&features.EnterpriseSSO); err != nil {
		return fmt.Errorf("enterprise sso: %w", err)
	}

	return nil
}

// validateMFA validates MFA configuration
func validateMFA(mfa *MFAConfig) error {
	if mfa.TOTP.Enabled {
		if mfa.TOTP.Period < 15 || mfa.TOTP.Period > 300 {
			return ErrInvalidTOTPPeriod
		}
		if mfa.TOTP.Digits < 6 || mfa.TOTP.Digits > 8 {
			return ErrInvalidTOTPDigits
		}
		validAlgorithms := []string{"SHA1", "SHA256", "SHA512"}
		if !contains(validAlgorithms, mfa.TOTP.Algorithm) {
			return ErrInvalidTOTPAlgorithm
		}
	}

	if mfa.SMS.Enabled {
		if mfa.SMS.Provider == "" {
			return ErrMissingSMSProvider
		}
		if mfa.SMS.APIKey == "" {
			return ErrMissingSMSAPIKey
		}
	}

	if mfa.Email.Enabled {
		if mfa.Email.Provider == "" {
			return ErrMissingEmailProvider
		}
		if mfa.Email.From == "" {
			return ErrMissingEmailFrom
		}
	}

	if mfa.WebAuthn.Enabled {
		if mfa.WebAuthn.RPID == "" {
			return ErrMissingWebAuthnRPID
		}
		if len(mfa.WebAuthn.RPOrigin) == 0 {
			return ErrMissingWebAuthnRPOrigin
		}
		for _, origin := range mfa.WebAuthn.RPOrigin {
			if _, err := url.Parse(origin); err != nil {
				return ErrInvalidWebAuthnRPOrigin
			}
		}
	}

	return nil
}

// validateSocialAuth validates social authentication configuration
func validateSocialAuth(social *SocialAuthConfig) error {
	if err := validateOAuth("google", &social.Google); err != nil {
		return err
	}
	if err := validateOAuth("facebook", &social.Facebook); err != nil {
		return err
	}
	if err := validateOAuth("github", &social.GitHub); err != nil {
		return err
	}
	return nil
}

// validateOAuth validates OAuth configuration
func validateOAuth(provider string, oauth *OAuthConfig) error {
	if oauth.Enabled {
		if oauth.ClientID == "" {
			return fmt.Errorf("%s oauth client id is required", provider)
		}
		if oauth.ClientSecret == "" {
			return fmt.Errorf("%s oauth client secret is required", provider)
		}
		if oauth.RedirectURL == "" {
			return fmt.Errorf("%s oauth redirect url is required", provider)
		}
		if _, err := url.Parse(oauth.RedirectURL); err != nil {
			return fmt.Errorf("%s oauth redirect url is invalid: %w", provider, err)
		}
	}
	return nil
}

// validateEnterpriseSSO validates enterprise SSO configuration
func validateEnterpriseSSO(sso *EnterpriseSSO) error {
	if sso.SAML.Enabled {
		if sso.SAML.MetadataURL == "" && sso.SAML.EntityID == "" {
			return ErrMissingSAMLConfig
		}
		if sso.SAML.ACSURL == "" {
			return ErrMissingSAMLACSURL
		}
		if _, err := url.Parse(sso.SAML.ACSURL); err != nil {
			return ErrInvalidSAMLACSURL
		}
	}

	if sso.OIDC.Enabled {
		if sso.OIDC.IssuerURL == "" {
			return ErrMissingOIDCIssuer
		}
		if _, err := url.Parse(sso.OIDC.IssuerURL); err != nil {
			return ErrInvalidOIDCIssuer
		}
		if sso.OIDC.ClientID == "" {
			return ErrMissingOIDCClientID
		}
		if sso.OIDC.ClientSecret == "" {
			return ErrMissingOIDCClientSecret
		}
	}

	if sso.LDAP.Enabled {
		if sso.LDAP.Host == "" {
			return ErrMissingLDAPHost
		}
		if sso.LDAP.Port < 1 || sso.LDAP.Port > 65535 {
			return ErrInvalidPort
		}
		if sso.LDAP.BaseDN == "" {
			return ErrMissingLDAPBaseDN
		}
	}

	return nil
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}
