package token

import (
	"testing"
	"time"

	"github.com/steve-mir/go-auth-system/internal/config"
)

func TestFactory_CreateTokenService(t *testing.T) {
	tests := []struct {
		name        string
		config      *config.TokenConfig
		wantType    string
		wantErr     bool
		errContains string
	}{
		{
			name: "create JWT service",
			config: &config.TokenConfig{
				Type:       "jwt",
				SigningKey: "test-signing-key",
				AccessTTL:  time.Minute * 15,
				RefreshTTL: time.Hour * 24,
				Issuer:     "test-issuer",
				Audience:   "test-audience",
			},
			wantType: "jwt",
			wantErr:  false,
		},
		{
			name: "create Paseto service",
			config: &config.TokenConfig{
				Type:          "paseto",
				EncryptionKey: "this-is-a-32-character-key-for-testing",
				AccessTTL:     time.Minute * 15,
				RefreshTTL:    time.Hour * 24,
				Issuer:        "test-issuer",
				Audience:      "test-audience",
			},
			wantType: "paseto",
			wantErr:  false,
		},
		{
			name: "case insensitive JWT",
			config: &config.TokenConfig{
				Type:       "JWT",
				SigningKey: "test-signing-key",
				AccessTTL:  time.Minute * 15,
				RefreshTTL: time.Hour * 24,
				Issuer:     "test-issuer",
				Audience:   "test-audience",
			},
			wantType: "jwt",
			wantErr:  false,
		},
		{
			name: "case insensitive Paseto",
			config: &config.TokenConfig{
				Type:          "PASETO",
				EncryptionKey: "this-is-a-32-character-key-for-testing",
				AccessTTL:     time.Minute * 15,
				RefreshTTL:    time.Hour * 24,
				Issuer:        "test-issuer",
				Audience:      "test-audience",
			},
			wantType: "paseto",
			wantErr:  false,
		},
		{
			name:        "nil config",
			config:      nil,
			wantErr:     true,
			errContains: "token configuration is required",
		},
		{
			name: "unsupported type",
			config: &config.TokenConfig{
				Type:       "unsupported",
				AccessTTL:  time.Minute * 15,
				RefreshTTL: time.Hour * 24,
			},
			wantErr:     true,
			errContains: "unsupported token service type",
		},
		{
			name: "missing type",
			config: &config.TokenConfig{
				AccessTTL:  time.Minute * 15,
				RefreshTTL: time.Hour * 24,
			},
			wantErr:     true,
			errContains: "token type is required",
		},
		{
			name: "JWT missing signing key",
			config: &config.TokenConfig{
				Type:       "jwt",
				AccessTTL:  time.Minute * 15,
				RefreshTTL: time.Hour * 24,
				Issuer:     "test-issuer",
				Audience:   "test-audience",
			},
			wantErr:     true,
			errContains: "JWT signing key is required",
		},
		{
			name: "Paseto missing encryption key",
			config: &config.TokenConfig{
				Type:       "paseto",
				AccessTTL:  time.Minute * 15,
				RefreshTTL: time.Hour * 24,
				Issuer:     "test-issuer",
				Audience:   "test-audience",
			},
			wantErr:     true,
			errContains: "Paseto encryption key is required",
		},
		{
			name: "invalid TTL - zero access TTL",
			config: &config.TokenConfig{
				Type:       "jwt",
				SigningKey: "test-signing-key",
				AccessTTL:  0,
				RefreshTTL: time.Hour * 24,
				Issuer:     "test-issuer",
				Audience:   "test-audience",
			},
			wantErr:     true,
			errContains: "access token TTL must be positive",
		},
		{
			name: "invalid TTL - refresh TTL less than access TTL",
			config: &config.TokenConfig{
				Type:       "jwt",
				SigningKey: "test-signing-key",
				AccessTTL:  time.Hour * 24,
				RefreshTTL: time.Minute * 15,
				Issuer:     "test-issuer",
				Audience:   "test-audience",
			},
			wantErr:     true,
			errContains: "refresh token TTL must be greater than access token TTL",
		},
		{
			name: "missing issuer",
			config: &config.TokenConfig{
				Type:       "jwt",
				SigningKey: "test-signing-key",
				AccessTTL:  time.Minute * 15,
				RefreshTTL: time.Hour * 24,
				Audience:   "test-audience",
			},
			wantErr:     true,
			errContains: "token issuer is required",
		},
		{
			name: "missing audience",
			config: &config.TokenConfig{
				Type:       "jwt",
				SigningKey: "test-signing-key",
				AccessTTL:  time.Minute * 15,
				RefreshTTL: time.Hour * 24,
				Issuer:     "test-issuer",
			},
			wantErr:     true,
			errContains: "token audience is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factory := NewFactory(tt.config)
			service, err := factory.CreateTokenService()

			if (err != nil) != tt.wantErr {
				t.Errorf("CreateTokenService() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if tt.errContains != "" && err != nil {
					if !contains(err.Error(), tt.errContains) {
						t.Errorf("CreateTokenService() error = %v, should contain %v", err, tt.errContains)
					}
				}
				return
			}

			if service == nil {
				t.Error("CreateTokenService() returned nil service")
				return
			}

			if service.GetTokenType() != tt.wantType {
				t.Errorf("CreateTokenService() type = %v, want %v", service.GetTokenType(), tt.wantType)
			}
		})
	}
}

func TestFactory_GetSupportedTypes(t *testing.T) {
	factory := NewFactory(nil)
	supportedTypes := factory.GetSupportedTypes()

	expectedTypes := []ServiceType{ServiceTypeJWT, ServiceTypePaseto}
	if len(supportedTypes) != len(expectedTypes) {
		t.Errorf("GetSupportedTypes() length = %v, want %v", len(supportedTypes), len(expectedTypes))
	}

	for _, expectedType := range expectedTypes {
		found := false
		for _, supportedType := range supportedTypes {
			if supportedType == expectedType {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("GetSupportedTypes() missing type %v", expectedType)
		}
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	if config.Type != "jwt" {
		t.Errorf("DefaultConfig() Type = %v, want jwt", config.Type)
	}

	if config.AccessTTL <= 0 {
		t.Error("DefaultConfig() AccessTTL should be positive")
	}

	if config.RefreshTTL <= 0 {
		t.Error("DefaultConfig() RefreshTTL should be positive")
	}

	if config.RefreshTTL <= config.AccessTTL {
		t.Error("DefaultConfig() RefreshTTL should be greater than AccessTTL")
	}

	if config.SigningKey == "" {
		t.Error("DefaultConfig() SigningKey should not be empty")
	}

	if config.Issuer == "" {
		t.Error("DefaultConfig() Issuer should not be empty")
	}

	if config.Audience == "" {
		t.Error("DefaultConfig() Audience should not be empty")
	}
}

func TestConfigBuilder(t *testing.T) {
	config := NewConfigBuilder().
		WithType("paseto").
		WithAccessTTL(time.Minute * 30).
		WithRefreshTTL(time.Hour * 48).
		WithEncryptionKey("test-encryption-key-32-characters").
		WithIssuer("test-builder-issuer").
		WithAudience("test-builder-audience").
		Build()

	if config.Type != "paseto" {
		t.Errorf("ConfigBuilder Type = %v, want paseto", config.Type)
	}

	if config.AccessTTL != time.Minute*30 {
		t.Errorf("ConfigBuilder AccessTTL = %v, want %v", config.AccessTTL, time.Minute*30)
	}

	if config.RefreshTTL != time.Hour*48 {
		t.Errorf("ConfigBuilder RefreshTTL = %v, want %v", config.RefreshTTL, time.Hour*48)
	}

	if config.EncryptionKey != "test-encryption-key-32-characters" {
		t.Errorf("ConfigBuilder EncryptionKey = %v, want test-encryption-key-32-characters", config.EncryptionKey)
	}

	if config.Issuer != "test-builder-issuer" {
		t.Errorf("ConfigBuilder Issuer = %v, want test-builder-issuer", config.Issuer)
	}

	if config.Audience != "test-builder-audience" {
		t.Errorf("ConfigBuilder Audience = %v, want test-builder-audience", config.Audience)
	}
}

func TestGetServiceInfo(t *testing.T) {
	serviceInfo := GetServiceInfo()

	if len(serviceInfo) != 2 {
		t.Errorf("GetServiceInfo() length = %v, want 2", len(serviceInfo))
	}

	// Check JWT info
	var jwtInfo *ServiceInfo
	var pasetoInfo *ServiceInfo

	for i := range serviceInfo {
		if serviceInfo[i].Type == ServiceTypeJWT {
			jwtInfo = &serviceInfo[i]
		} else if serviceInfo[i].Type == ServiceTypePaseto {
			pasetoInfo = &serviceInfo[i]
		}
	}

	if jwtInfo == nil {
		t.Error("GetServiceInfo() missing JWT service info")
	} else {
		if jwtInfo.Name == "" {
			t.Error("JWT service info missing name")
		}
		if jwtInfo.Description == "" {
			t.Error("JWT service info missing description")
		}
		if len(jwtInfo.Features) == 0 {
			t.Error("JWT service info missing features")
		}
	}

	if pasetoInfo == nil {
		t.Error("GetServiceInfo() missing Paseto service info")
	} else {
		if pasetoInfo.Name == "" {
			t.Error("Paseto service info missing name")
		}
		if pasetoInfo.Description == "" {
			t.Error("Paseto service info missing description")
		}
		if len(pasetoInfo.Features) == 0 {
			t.Error("Paseto service info missing features")
		}
	}
}

func TestValidateServiceType(t *testing.T) {
	tests := []struct {
		name        string
		serviceType string
		wantErr     bool
	}{
		{
			name:        "valid JWT",
			serviceType: "jwt",
			wantErr:     false,
		},
		{
			name:        "valid Paseto",
			serviceType: "paseto",
			wantErr:     false,
		},
		{
			name:        "valid JWT uppercase",
			serviceType: "JWT",
			wantErr:     false,
		},
		{
			name:        "valid Paseto mixed case",
			serviceType: "PaSeTO",
			wantErr:     false,
		},
		{
			name:        "invalid type",
			serviceType: "invalid",
			wantErr:     true,
		},
		{
			name:        "empty type",
			serviceType: "",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateServiceType(tt.serviceType)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateServiceType() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFactory_Integration(t *testing.T) {
	// Test creating both services and ensuring they work
	jwtConfig := &config.TokenConfig{
		Type:       "jwt",
		SigningKey: "test-signing-key-for-integration",
		AccessTTL:  time.Minute * 15,
		RefreshTTL: time.Hour * 24,
		Issuer:     "integration-test",
		Audience:   "integration-test-users",
	}

	pasetoConfig := &config.TokenConfig{
		Type:          "paseto",
		EncryptionKey: "integration-test-32-character-key",
		AccessTTL:     time.Minute * 15,
		RefreshTTL:    time.Hour * 24,
		Issuer:        "integration-test",
		Audience:      "integration-test-users",
	}

	// Test JWT service creation and basic functionality
	jwtFactory := NewFactory(jwtConfig)
	jwtService, err := jwtFactory.CreateTokenService()
	if err != nil {
		t.Fatalf("Failed to create JWT service: %v", err)
	}

	if jwtService.GetTokenType() != "jwt" {
		t.Errorf("JWT service type = %v, want jwt", jwtService.GetTokenType())
	}

	// Test Paseto service creation and basic functionality
	pasetoFactory := NewFactory(pasetoConfig)
	pasetoService, err := pasetoFactory.CreateTokenService()
	if err != nil {
		t.Fatalf("Failed to create Paseto service: %v", err)
	}

	if pasetoService.GetTokenType() != "paseto" {
		t.Errorf("Paseto service type = %v, want paseto", pasetoService.GetTokenType())
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			func() bool {
				for i := 0; i <= len(s)-len(substr); i++ {
					if s[i:i+len(substr)] == substr {
						return true
					}
				}
				return false
			}())))
}
