package config

import (
	"strconv"
	"time"
)

// setDefaults sets default configuration values
func setDefaults(config *Config) {
	// Server defaults
	config.Server.Host = "0.0.0.0"
	config.Server.Port = 8080
	config.Server.GRPCPort = 9090
	config.Server.ReadTimeout = 30 * time.Second
	config.Server.WriteTimeout = 30 * time.Second
	config.Server.IdleTimeout = 120 * time.Second
	config.Server.TLS.Enabled = false

	// Database defaults
	config.Database.Host = "localhost"
	config.Database.Port = 5432
	config.Database.Name = "auth_system"
	config.Database.User = "postgres"
	config.Database.Password = "postgres"
	config.Database.SSLMode = "disable"
	config.Database.MaxOpenConns = 25
	config.Database.MaxIdleConns = 5
	config.Database.ConnMaxLifetime = 5 * time.Minute
	config.Database.ConnMaxIdleTime = 5 * time.Minute
	config.Database.ConnectTimeout = 10

	// Redis defaults
	config.Redis.Host = "localhost"
	config.Redis.Port = 6379
	config.Redis.DB = 0
	config.Redis.PoolSize = 10
	config.Redis.MinIdleConns = 2
	config.Redis.DialTimeout = 5 * time.Second
	config.Redis.ReadTimeout = 3 * time.Second
	config.Redis.WriteTimeout = 3 * time.Second

	// Security defaults
	setSecurityDefaults(&config.Security)

	// Features defaults
	setFeaturesDefaults(&config.Features)

	// External defaults
	setExternalDefaults(&config.External)
}

// setSecurityDefaults sets default security configuration
func setSecurityDefaults(security *SecurityConfig) {
	// Password hash defaults
	security.PasswordHash.Algorithm = "argon2"
	security.PasswordHash.Argon2.Memory = 64 * 1024 // 64 MB
	security.PasswordHash.Argon2.Iterations = 3
	security.PasswordHash.Argon2.Parallelism = 2
	security.PasswordHash.Argon2.SaltLength = 16
	security.PasswordHash.Argon2.KeyLength = 32
	security.PasswordHash.Bcrypt.Cost = 12

	// Token defaults
	security.Token.Type = "jwt"
	security.Token.AccessTTL = 15 * time.Minute
	security.Token.RefreshTTL = 7 * 24 * time.Hour // 7 days
	security.Token.Issuer = "go-auth-system"
	security.Token.Audience = "go-auth-system"

	// Rate limit defaults
	security.RateLimit.Enabled = true
	security.RateLimit.RequestsPerMin = 100
	security.RateLimit.BurstSize = 10
	security.RateLimit.WindowSize = 1 * time.Minute
	security.RateLimit.CleanupPeriod = 5 * time.Minute

	// Encryption defaults
	security.Encryption.Algorithm = "aes-256-gcm"
	security.Encryption.KeySize = 32
	security.Encryption.KeyRotation = false
	security.Encryption.KeyManagement = "local"
}

// setFeaturesDefaults sets default feature configuration
func setFeaturesDefaults(features *FeaturesConfig) {
	// MFA defaults
	features.MFA.Enabled = false
	features.MFA.TOTP.Enabled = false
	features.MFA.TOTP.Issuer = "go-auth-system"
	features.MFA.TOTP.Period = 30
	features.MFA.TOTP.Digits = 6
	features.MFA.TOTP.Algorithm = "SHA1"
	features.MFA.SMS.Enabled = false
	features.MFA.Email.Enabled = false
	features.MFA.Email.Subject = "Your verification code"
	features.MFA.WebAuthn.Enabled = false
	features.MFA.WebAuthn.RPDisplayName = "Go Auth System"

	// Social auth defaults
	features.SocialAuth.Google.Enabled = false
	features.SocialAuth.Facebook.Enabled = false
	features.SocialAuth.GitHub.Enabled = false

	// Enterprise SSO defaults
	features.EnterpriseSSO.SAML.Enabled = false
	features.EnterpriseSSO.OIDC.Enabled = false
	features.EnterpriseSSO.LDAP.Enabled = false
	features.EnterpriseSSO.LDAP.Port = 389
	features.EnterpriseSSO.LDAP.TLS = false

	// Admin dashboard defaults
	features.AdminDashboard.Enabled = true
	features.AdminDashboard.Path = "/admin"
	features.AdminDashboard.Title = "Go Auth System Admin"

	// Audit logging defaults
	features.AuditLogging.Enabled = true
	features.AuditLogging.Level = "info"
	features.AuditLogging.Format = "json"
	features.AuditLogging.Output = "stdout"
	features.AuditLogging.Retention = 90
}

// setExternalDefaults sets default external service configuration
func setExternalDefaults(external *ExternalConfig) {
	// Monitoring defaults
	external.Monitoring.Enabled = true
	external.Monitoring.Prometheus.Enabled = true
	external.Monitoring.Prometheus.Path = "/metrics"
	external.Monitoring.Prometheus.Port = 8081

	// Error tracker defaults
	external.Monitoring.ErrorTracker.Enabled = true
	external.Monitoring.ErrorTracker.MaxErrors = 10000
	external.Monitoring.ErrorTracker.RetentionPeriod = 7 * 24 * time.Hour // 7 days
	external.Monitoring.ErrorTracker.AlertingEnabled = true
	external.Monitoring.ErrorTracker.AlertBuffer = 1000
	external.Monitoring.ErrorTracker.DefaultSeverity = "medium"
	external.Monitoring.ErrorTracker.EnableStackTrace = true
	external.Monitoring.ErrorTracker.EnableGrouping = true

	// Log aggregator defaults
	external.Monitoring.Aggregator.Enabled = true
	external.Monitoring.Aggregator.MaxEntries = 100000
	external.Monitoring.Aggregator.RetentionPeriod = 24 * time.Hour
	external.Monitoring.Aggregator.AggregationLevels = []string{"minute", "hour", "day"}
	external.Monitoring.Aggregator.PatternDetection = true
	external.Monitoring.Aggregator.MetricsEnabled = true

	// Tracing defaults
	external.Monitoring.Tracing.Enabled = true
	external.Monitoring.Tracing.ServiceName = "go-auth-system"
	external.Monitoring.Tracing.ServiceVersion = "1.0.0"
	external.Monitoring.Tracing.SampleRate = 0.1 // 10% sampling

	// Logging defaults
	external.Logging.Level = "info"
	external.Logging.Format = "json"
	external.Logging.Output = "stdout"
}

// parsePort parses a port string to integer
func parsePort(portStr string) (int, error) {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, err
	}
	if port < 1 || port > 65535 {
		return 0, ErrInvalidPort
	}
	return port, nil
}
