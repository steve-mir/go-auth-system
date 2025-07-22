package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the complete application configuration
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	Redis    RedisConfig    `yaml:"redis"`
	Security SecurityConfig `yaml:"security"`
	Features FeaturesConfig `yaml:"features"`
	External ExternalConfig `yaml:"external"`
}

// ServerConfig contains server-related configuration
type ServerConfig struct {
	Host         string        `yaml:"host"`
	Port         int           `yaml:"port"`
	GRPCPort     int           `yaml:"grpc_port"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	IdleTimeout  time.Duration `yaml:"idle_timeout"`
	TLS          TLSConfig     `yaml:"tls"`
	Environment  string        `yaml:"environment"`
}

// TLSConfig contains TLS configuration
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// DatabaseConfig contains database connection configuration
type DatabaseConfig struct {
	Host            string        `yaml:"host"`
	Port            int           `yaml:"port"`
	Name            string        `yaml:"name"`
	User            string        `yaml:"user"`
	Password        string        `yaml:"password"`
	SSLMode         string        `yaml:"ssl_mode"`
	MaxOpenConns    int           `yaml:"max_open_conns"`
	MaxIdleConns    int           `yaml:"max_idle_conns"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime"`
	ConnMaxIdleTime time.Duration `yaml:"conn_max_idle_time"`
	ConnectTimeout  int           `yaml:"connect_timeout"`
}

// RedisConfig contains Redis connection configuration
type RedisConfig struct {
	Host         string        `yaml:"host"`
	Port         int           `yaml:"port"`
	Password     string        `yaml:"password"`
	DB           int           `yaml:"db"`
	PoolSize     int           `yaml:"pool_size"`
	MinIdleConns int           `yaml:"min_idle_conns"`
	DialTimeout  time.Duration `yaml:"dial_timeout"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
}

// SecurityConfig contains all security-related configuration
type SecurityConfig struct {
	PasswordHash PasswordHashConfig `yaml:"password_hash"`
	Token        TokenConfig        `yaml:"token"`
	RateLimit    RateLimitConfig    `yaml:"rate_limit"`
	Encryption   EncryptionConfig   `yaml:"encryption"`
}

// PasswordHashConfig contains password hashing configuration
type PasswordHashConfig struct {
	Algorithm string       `yaml:"algorithm"` // "argon2" or "bcrypt"
	Argon2    Argon2Config `yaml:"argon2"`
	Bcrypt    BcryptConfig `yaml:"bcrypt"`
}

// Argon2Config contains Argon2 specific configuration
type Argon2Config struct {
	Memory      uint32 `yaml:"memory"`
	Iterations  uint32 `yaml:"iterations"`
	Parallelism uint8  `yaml:"parallelism"`
	SaltLength  uint32 `yaml:"salt_length"`
	KeyLength   uint32 `yaml:"key_length"`
}

// BcryptConfig contains bcrypt specific configuration
type BcryptConfig struct {
	Cost int `yaml:"cost"`
}

// TokenConfig contains token management configuration
type TokenConfig struct {
	Type          string        `yaml:"type"` // "jwt" or "paseto"
	AccessTTL     time.Duration `yaml:"access_ttl"`
	RefreshTTL    time.Duration `yaml:"refresh_ttl"`
	SigningKey    string        `yaml:"signing_key"`
	EncryptionKey string        `yaml:"encryption_key"`
	Issuer        string        `yaml:"issuer"`
	Audience      string        `yaml:"audience"`
}

// RateLimitConfig contains rate limiting configuration
type RateLimitConfig struct {
	Enabled        bool          `yaml:"enabled"`
	RequestsPerMin int           `yaml:"requests_per_minute"`
	BurstSize      int           `yaml:"burst_size"`
	WindowSize     time.Duration `yaml:"window_size"`
	CleanupPeriod  time.Duration `yaml:"cleanup_period"`
}

// EncryptionConfig contains data encryption configuration
type EncryptionConfig struct {
	Algorithm     string `yaml:"algorithm"` // "aes-256-gcm"
	KeySize       int    `yaml:"key_size"`
	MasterKey     string `yaml:"master_key"`
	KeyRotation   bool   `yaml:"key_rotation"`
	KeyManagement string `yaml:"key_management"` // "local" or "vault"
}

// FeaturesConfig contains feature flags and optional functionality
type FeaturesConfig struct {
	MFA            MFAConfig            `yaml:"mfa"`
	SocialAuth     SocialAuthConfig     `yaml:"social_auth"`
	EnterpriseSSO  EnterpriseSSO        `yaml:"enterprise_sso"`
	AdminDashboard AdminDashboardConfig `yaml:"admin_dashboard"`
	AuditLogging   AuditLoggingConfig   `yaml:"audit_logging"`
}

// MFAConfig contains multi-factor authentication configuration
type MFAConfig struct {
	Enabled  bool           `yaml:"enabled"`
	TOTP     TOTPConfig     `yaml:"totp"`
	SMS      SMSConfig      `yaml:"sms"`
	Email    EmailConfig    `yaml:"email"`
	WebAuthn WebAuthnConfig `yaml:"webauthn"`
}

// TOTPConfig contains TOTP configuration
type TOTPConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Issuer    string `yaml:"issuer"`
	Period    int    `yaml:"period"`
	Digits    int    `yaml:"digits"`
	Algorithm string `yaml:"algorithm"`
}

// SMSConfig contains SMS MFA configuration
type SMSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Provider string `yaml:"provider"`
	APIKey   string `yaml:"api_key"`
	From     string `yaml:"from"`
}

// EmailConfig contains email MFA configuration
type EmailConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Provider string `yaml:"provider"`
	From     string `yaml:"from"`
	Subject  string `yaml:"subject"`
}

// WebAuthnConfig contains WebAuthn configuration
type WebAuthnConfig struct {
	Enabled        bool     `yaml:"enabled"`
	RPDisplayName  string   `yaml:"rp_display_name"`
	RPID           string   `yaml:"rp_id"`
	RPName         string   `yaml:"rp_name"`
	RPOrigin       string   `yaml:"rp_origin"`
	AllowedOrigins []string `yaml:"allowed_origins"`
}

// SocialAuthConfig contains social authentication configuration
type SocialAuthConfig struct {
	Google   OAuthConfig `yaml:"google"`
	Facebook OAuthConfig `yaml:"facebook"`
	GitHub   OAuthConfig `yaml:"github"`
}

// OAuthConfig contains OAuth provider configuration
type OAuthConfig struct {
	Enabled      bool     `yaml:"enabled"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	RedirectURL  string   `yaml:"redirect_url"`
	Scopes       []string `yaml:"scopes"`
}

// EnterpriseSSO contains enterprise SSO configuration
type EnterpriseSSO struct {
	SAML SAMLConfig `yaml:"saml"`
	OIDC OIDCConfig `yaml:"oidc"`
	LDAP LDAPConfig `yaml:"ldap"`
}

// SAMLConfig contains SAML 2.0 configuration
type SAMLConfig struct {
	Enabled     bool   `yaml:"enabled"`
	MetadataURL string `yaml:"metadata_url"`
	EntityID    string `yaml:"entity_id"`
	ACSURL      string `yaml:"acs_url"`
	Certificate string `yaml:"certificate"`
	PrivateKey  string `yaml:"private_key"`
}

// OIDCConfig contains OpenID Connect configuration
type OIDCConfig struct {
	Enabled      bool     `yaml:"enabled"`
	IssuerURL    string   `yaml:"issuer_url"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	RedirectURL  string   `yaml:"redirect_url"`
	Scopes       []string `yaml:"scopes"`
}

// LDAPConfig contains LDAP/Active Directory configuration
type LDAPConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	BaseDN       string `yaml:"base_dn"`
	BindDN       string `yaml:"bind_dn"`
	BindPassword string `yaml:"bind_password"`
	UserFilter   string `yaml:"user_filter"`
	GroupFilter  string `yaml:"group_filter"`
	TLS          bool   `yaml:"tls"`
}

// AdminDashboardConfig contains admin dashboard configuration
type AdminDashboardConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
	Title   string `yaml:"title"`
}

// AuditLoggingConfig contains audit logging configuration
type AuditLoggingConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Level     string `yaml:"level"`
	Format    string `yaml:"format"`
	Output    string `yaml:"output"`
	Retention int    `yaml:"retention_days"`
}

// ExternalConfig contains external service configuration
type ExternalConfig struct {
	Monitoring MonitoringConfig `yaml:"monitoring"`
	Logging    LoggingConfig    `yaml:"logging"`
}

// MonitoringConfig contains monitoring configuration
type MonitoringConfig struct {
	Enabled    bool             `yaml:"enabled"`
	Prometheus PrometheusConfig `yaml:"prometheus"`
}

// PrometheusConfig contains Prometheus configuration
type PrometheusConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
	Port    int    `yaml:"port"`
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	Output string `yaml:"output"`
}

// Load loads configuration from file and environment variables
func Load(configPath string) (*Config, error) {
	config := &Config{}

	// Set defaults
	setDefaults(config)

	// Load from file if provided
	if configPath != "" {
		if err := loadFromFile(config, configPath); err != nil {
			return nil, fmt.Errorf("failed to load config from file: %w", err)
		}
	}

	// Override with environment variables
	loadFromEnv(config)

	// Validate configuration
	if err := validate(config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return config, nil
}

// loadFromFile loads configuration from YAML file
func loadFromFile(config *Config, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, config); err != nil {
		return fmt.Errorf("failed to parse YAML config: %w", err)
	}

	return nil
}

// loadFromEnv loads configuration from environment variables
func loadFromEnv(config *Config) {
	// Server configuration
	config.Server.Host = getEnvString("SERVER_HOST", config.Server.Host)
	config.Server.Environment = getEnvString("Environment", config.Server.Environment)
	config.Server.Port = getEnvInt("SERVER_PORT", config.Server.Port)
	config.Server.GRPCPort = getEnvInt("SERVER_GRPC_PORT", config.Server.GRPCPort)
	config.Server.ReadTimeout = getEnvDuration("SERVER_READ_TIMEOUT", config.Server.ReadTimeout)
	config.Server.WriteTimeout = getEnvDuration("SERVER_WRITE_TIMEOUT", config.Server.WriteTimeout)
	config.Server.IdleTimeout = getEnvDuration("SERVER_IDLE_TIMEOUT", config.Server.IdleTimeout)

	// TLS configuration
	config.Server.TLS.Enabled = getEnvBool("TLS_ENABLED", config.Server.TLS.Enabled)
	config.Server.TLS.CertFile = getEnvString("TLS_CERT_FILE", config.Server.TLS.CertFile)
	config.Server.TLS.KeyFile = getEnvString("TLS_KEY_FILE", config.Server.TLS.KeyFile)

	// Database configuration
	config.Database.Host = getEnvString("DB_HOST", config.Database.Host)
	config.Database.Port = getEnvInt("DB_PORT", config.Database.Port)
	config.Database.Name = getEnvString("DB_NAME", config.Database.Name)
	config.Database.User = getEnvString("DB_USER", config.Database.User)
	config.Database.Password = getEnvString("DB_PASSWORD", config.Database.Password)
	config.Database.SSLMode = getEnvString("DB_SSL_MODE", config.Database.SSLMode)
	config.Database.MaxOpenConns = getEnvInt("DB_MAX_OPEN_CONNS", config.Database.MaxOpenConns)
	config.Database.MaxIdleConns = getEnvInt("DB_MAX_IDLE_CONNS", config.Database.MaxIdleConns)
	config.Database.ConnMaxLifetime = getEnvDuration("DB_CONN_MAX_LIFETIME", config.Database.ConnMaxLifetime)
	config.Database.ConnMaxIdleTime = getEnvDuration("DB_CONN_MAX_IDLE_TIME", config.Database.ConnMaxIdleTime)
	config.Database.ConnectTimeout = getEnvInt("DB_CONNECT_TIMEOUT", config.Database.ConnectTimeout)

	// Redis configuration
	config.Redis.Host = getEnvString("REDIS_HOST", config.Redis.Host)
	config.Redis.Port = getEnvInt("REDIS_PORT", config.Redis.Port)
	config.Redis.Password = getEnvString("REDIS_PASSWORD", config.Redis.Password)
	config.Redis.DB = getEnvInt("REDIS_DB", config.Redis.DB)
	config.Redis.PoolSize = getEnvInt("REDIS_POOL_SIZE", config.Redis.PoolSize)
	config.Redis.MinIdleConns = getEnvInt("REDIS_MIN_IDLE_CONNS", config.Redis.MinIdleConns)
	config.Redis.DialTimeout = getEnvDuration("REDIS_DIAL_TIMEOUT", config.Redis.DialTimeout)
	config.Redis.ReadTimeout = getEnvDuration("REDIS_READ_TIMEOUT", config.Redis.ReadTimeout)
	config.Redis.WriteTimeout = getEnvDuration("REDIS_WRITE_TIMEOUT", config.Redis.WriteTimeout)

	// Security configuration
	config.Security.PasswordHash.Algorithm = getEnvString("PASSWORD_HASH_ALGORITHM", config.Security.PasswordHash.Algorithm)
	config.Security.Token.Type = getEnvString("TOKEN_TYPE", config.Security.Token.Type)
	config.Security.Token.SigningKey = getEnvString("JWT_SIGNING_KEY", config.Security.Token.SigningKey)
	config.Security.Token.EncryptionKey = getEnvString("TOKEN_ENCRYPTION_KEY", config.Security.Token.EncryptionKey)
	config.Security.Token.AccessTTL = getEnvDuration("TOKEN_ACCESS_TTL", config.Security.Token.AccessTTL)
	config.Security.Token.RefreshTTL = getEnvDuration("TOKEN_REFRESH_TTL", config.Security.Token.RefreshTTL)
	config.Security.Token.Issuer = getEnvString("TOKEN_ISSUER", config.Security.Token.Issuer)
	config.Security.Token.Audience = getEnvString("TOKEN_AUDIENCE", config.Security.Token.Audience)

	// Encryption configuration
	config.Security.Encryption.MasterKey = getEnvString("ENCRYPTION_MASTER_KEY", config.Security.Encryption.MasterKey)
	config.Security.Encryption.KeyManagement = getEnvString("KEY_MANAGEMENT", config.Security.Encryption.KeyManagement)

	// Rate limiting configuration
	config.Security.RateLimit.Enabled = getEnvBool("RATE_LIMIT_ENABLED", config.Security.RateLimit.Enabled)
	config.Security.RateLimit.RequestsPerMin = getEnvInt("RATE_LIMIT_REQUESTS_PER_MIN", config.Security.RateLimit.RequestsPerMin)
	config.Security.RateLimit.BurstSize = getEnvInt("RATE_LIMIT_BURST_SIZE", config.Security.RateLimit.BurstSize)

	// Feature flags
	config.Features.MFA.Enabled = getEnvBool("MFA_ENABLED", config.Features.MFA.Enabled)
	config.Features.AdminDashboard.Enabled = getEnvBool("ADMIN_DASHBOARD_ENABLED", config.Features.AdminDashboard.Enabled)
	config.Features.AuditLogging.Enabled = getEnvBool("AUDIT_LOGGING_ENABLED", config.Features.AuditLogging.Enabled)

	// External services
	config.External.Monitoring.Enabled = getEnvBool("MONITORING_ENABLED", config.External.Monitoring.Enabled)
	config.External.Monitoring.Prometheus.Enabled = getEnvBool("PROMETHEUS_ENABLED", config.External.Monitoring.Prometheus.Enabled)
	config.External.Monitoring.Prometheus.Port = getEnvInt("PROMETHEUS_PORT", config.External.Monitoring.Prometheus.Port)
}
