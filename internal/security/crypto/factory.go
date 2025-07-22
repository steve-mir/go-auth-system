package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// EncryptionConfig represents encryption configuration
type EncryptionConfig struct {
	Algorithm     string `yaml:"algorithm"`      // "aes-256-gcm"
	KeySize       int    `yaml:"key_size"`       // 32 for AES-256
	MasterKey     string `yaml:"master_key"`     // Hex-encoded master key
	KeyRotation   bool   `yaml:"key_rotation"`   // Enable key rotation
	KeyManagement string `yaml:"key_management"` // "local" or "vault"
}

// EncryptionServiceFactory creates encryption services based on configuration
type EncryptionServiceFactory struct {
	config *EncryptionConfig
}

// NewEncryptionServiceFactory creates a new encryption service factory
func NewEncryptionServiceFactory(config *EncryptionConfig) *EncryptionServiceFactory {
	return &EncryptionServiceFactory{
		config: config,
	}
}

// CreateEncryptionService creates an encryption service based on configuration
func (f *EncryptionServiceFactory) CreateEncryptionService() (*EncryptionService, error) {
	// Validate configuration
	if err := f.validateConfig(); err != nil {
		return nil, fmt.Errorf("invalid encryption config: %w", err)
	}

	// Create key provider based on configuration
	keyProvider, err := f.createKeyProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to create key provider: %w", err)
	}

	// Create encryption service
	service, err := NewEncryptionService(keyProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption service: %w", err)
	}

	return service, nil
}

// validateConfig validates the encryption configuration
func (f *EncryptionServiceFactory) validateConfig() error {
	if f.config == nil {
		return fmt.Errorf("encryption config is nil")
	}

	// Validate algorithm
	if f.config.Algorithm != "aes-256-gcm" {
		return fmt.Errorf("unsupported encryption algorithm: %s", f.config.Algorithm)
	}

	// Validate key size
	if f.config.KeySize != 32 {
		return fmt.Errorf("invalid key size for AES-256: %d, expected 32", f.config.KeySize)
	}

	// Validate key management type
	switch f.config.KeyManagement {
	case "local", "vault":
		// Valid options
	case "":
		f.config.KeyManagement = "local" // Default to local
	default:
		return fmt.Errorf("unsupported key management type: %s", f.config.KeyManagement)
	}

	return nil
}

// createKeyProvider creates a key provider based on configuration
func (f *EncryptionServiceFactory) createKeyProvider() (KeyProvider, error) {
	switch f.config.KeyManagement {
	case "local":
		return f.createLocalKeyProvider()
	case "vault":
		return f.createVaultKeyProvider()
	default:
		return nil, fmt.Errorf("unsupported key management type: %s", f.config.KeyManagement)
	}
}

// createLocalKeyProvider creates a local static key provider
func (f *EncryptionServiceFactory) createLocalKeyProvider() (KeyProvider, error) {
	var key []byte
	var err error

	if f.config.MasterKey != "" {
		// Use provided master key
		key, err = hex.DecodeString(f.config.MasterKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decode master key: %w", err)
		}

		if len(key) != f.config.KeySize {
			return nil, fmt.Errorf("master key size mismatch: got %d, expected %d", len(key), f.config.KeySize)
		}
	} else {
		// Generate a new key
		key = make([]byte, f.config.KeySize)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("failed to generate encryption key: %w", err)
		}
	}

	keyID := "local-key-1"
	return NewStaticKeyProvider(key, keyID), nil
}

// createVaultKeyProvider creates a Vault-based key provider
func (f *EncryptionServiceFactory) createVaultKeyProvider() (KeyProvider, error) {
	// For now, return an error as Vault integration is not implemented
	// In a real implementation, this would integrate with HashiCorp Vault
	return nil, fmt.Errorf("vault key management not implemented yet")
}

// GenerateKey generates a new encryption key of the specified size
func GenerateKey(size int) ([]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("invalid key size: %d", size)
	}

	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	return key, nil
}

// GenerateKeyHex generates a new encryption key and returns it as hex string
func GenerateKeyHex(size int) (string, error) {
	key, err := GenerateKey(size)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(key), nil
}

// ValidateKey validates that a key meets the requirements
func ValidateKey(key []byte, expectedSize int) error {
	if len(key) != expectedSize {
		return fmt.Errorf("invalid key size: got %d, expected %d", len(key), expectedSize)
	}

	// Check if key is all zeros (weak key)
	allZeros := true
	for _, b := range key {
		if b != 0 {
			allZeros = false
			break
		}
	}

	if allZeros {
		return fmt.Errorf("key cannot be all zeros")
	}

	return nil
}

// ValidateKeyHex validates a hex-encoded key
func ValidateKeyHex(keyHex string, expectedSize int) error {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return fmt.Errorf("invalid hex key: %w", err)
	}

	return ValidateKey(key, expectedSize)
}
