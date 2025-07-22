package token

import (
	"fmt"
	"strings"
	"time"

	"github.com/steve-mir/go-auth-system/internal/config"
)

// ServiceType represents the type of token service
type ServiceType string

const (
	ServiceTypeJWT    ServiceType = "jwt"
	ServiceTypePaseto ServiceType = "paseto"
)

// Factory creates token services based on configuration
type Factory struct {
	config *config.TokenConfig
}

// NewFactory creates a new token service factory
func NewFactory(cfg *config.TokenConfig) *Factory {
	return &Factory{
		config: cfg,
	}
}

// CreateTokenService creates a token service based on configuration
func (f *Factory) CreateTokenService() (TokenService, error) {
	if f.config == nil {
		return nil, fmt.Errorf("token configuration is required")
	}

	// Validate configuration
	if err := f.validateConfig(); err != nil {
		return nil, fmt.Errorf("invalid token configuration: %w", err)
	}

	// Create service based on type
	serviceType := ServiceType(strings.ToLower(f.config.Type))
	switch serviceType {
	case ServiceTypeJWT:
		return NewJWTService(f.config)
	case ServiceTypePaseto:
		return NewPasetoService(f.config)
	default:
		return nil, fmt.Errorf("unsupported token service type: %s", f.config.Type)
	}
}

// GetSupportedTypes returns the list of supported token service types
func (f *Factory) GetSupportedTypes() []ServiceType {
	return []ServiceType{
		ServiceTypeJWT,
		ServiceTypePaseto,
	}
}

// validateConfig validates the token configuration
func (f *Factory) validateConfig() error {
	if f.config.Type == "" {
		return fmt.Errorf("token type is required")
	}

	serviceType := ServiceType(strings.ToLower(f.config.Type))

	// Validate service type
	supported := false
	for _, supportedType := range f.GetSupportedTypes() {
		if serviceType == supportedType {
			supported = true
			break
		}
	}
	if !supported {
		return fmt.Errorf("unsupported token type: %s", f.config.Type)
	}

	// Validate TTL values
	if f.config.AccessTTL <= 0 {
		return fmt.Errorf("access token TTL must be positive")
	}
	if f.config.RefreshTTL <= 0 {
		return fmt.Errorf("refresh token TTL must be positive")
	}
	if f.config.RefreshTTL <= f.config.AccessTTL {
		return fmt.Errorf("refresh token TTL must be greater than access token TTL")
	}

	// Validate keys based on service type
	switch serviceType {
	case ServiceTypeJWT:
		if f.config.SigningKey == "" {
			return fmt.Errorf("JWT signing key is required")
		}
	case ServiceTypePaseto:
		if f.config.EncryptionKey == "" {
			return fmt.Errorf("Paseto encryption key is required")
		}
		if len(f.config.EncryptionKey) < 32 {
			return fmt.Errorf("Paseto encryption key must be at least 32 characters")
		}
	}

	// Validate optional fields
	if f.config.Issuer == "" {
		return fmt.Errorf("token issuer is required")
	}
	if f.config.Audience == "" {
		return fmt.Errorf("token audience is required")
	}

	return nil
}

// DefaultConfig returns a default token configuration
func DefaultConfig() *config.TokenConfig {
	return &config.TokenConfig{
		Type:          "jwt",
		AccessTTL:     time.Minute * 15,   // 15 minutes
		RefreshTTL:    time.Hour * 24 * 7, // 7 days
		SigningKey:    "your-secret-key-here",
		EncryptionKey: "your-32-character-encryption-key",
		Issuer:        "go-auth-system",
		Audience:      "go-auth-system-users",
	}
}

// ConfigBuilder provides a fluent interface for building token configuration
type ConfigBuilder struct {
	config *config.TokenConfig
}

// NewConfigBuilder creates a new configuration builder
func NewConfigBuilder() *ConfigBuilder {
	return &ConfigBuilder{
		config: DefaultConfig(),
	}
}

// WithType sets the token service type
func (b *ConfigBuilder) WithType(tokenType string) *ConfigBuilder {
	b.config.Type = tokenType
	return b
}

// WithAccessTTL sets the access token TTL
func (b *ConfigBuilder) WithAccessTTL(ttl time.Duration) *ConfigBuilder {
	b.config.AccessTTL = ttl
	return b
}

// WithRefreshTTL sets the refresh token TTL
func (b *ConfigBuilder) WithRefreshTTL(ttl time.Duration) *ConfigBuilder {
	b.config.RefreshTTL = ttl
	return b
}

// WithSigningKey sets the JWT signing key
func (b *ConfigBuilder) WithSigningKey(key string) *ConfigBuilder {
	b.config.SigningKey = key
	return b
}

// WithEncryptionKey sets the Paseto encryption key
func (b *ConfigBuilder) WithEncryptionKey(key string) *ConfigBuilder {
	b.config.EncryptionKey = key
	return b
}

// WithIssuer sets the token issuer
func (b *ConfigBuilder) WithIssuer(issuer string) *ConfigBuilder {
	b.config.Issuer = issuer
	return b
}

// WithAudience sets the token audience
func (b *ConfigBuilder) WithAudience(audience string) *ConfigBuilder {
	b.config.Audience = audience
	return b
}

// Build returns the built configuration
func (b *ConfigBuilder) Build() *config.TokenConfig {
	return b.config
}

// ServiceInfo provides information about a token service
type ServiceInfo struct {
	Type        ServiceType `json:"type"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Features    []string    `json:"features"`
}

// GetServiceInfo returns information about supported token services
func GetServiceInfo() []ServiceInfo {
	return []ServiceInfo{
		{
			Type:        ServiceTypeJWT,
			Name:        "JSON Web Token",
			Description: "Industry standard RFC 7519 token format",
			Features: []string{
				"Stateless",
				"Self-contained",
				"Widely supported",
				"Configurable signing algorithms",
				"Compact size",
			},
		},
		{
			Type:        ServiceTypePaseto,
			Name:        "Platform-Agnostic Security Tokens",
			Description: "Secure alternative to JWT with better defaults",
			Features: []string{
				"Encrypted by default",
				"Version-aware",
				"Misuse-resistant",
				"No algorithm confusion",
				"Built-in expiration",
			},
		},
	}
}

// ValidateServiceType checks if a service type is supported
func ValidateServiceType(serviceType string) error {
	normalizedType := ServiceType(strings.ToLower(serviceType))

	supportedTypes := []ServiceType{ServiceTypeJWT, ServiceTypePaseto}
	for _, supported := range supportedTypes {
		if normalizedType == supported {
			return nil
		}
	}

	return fmt.Errorf("unsupported token service type: %s", serviceType)
}
