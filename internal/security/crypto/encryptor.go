package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// Encryptor interface for data encryption/decryption
type Encryptor interface {
	Encrypt(data []byte) ([]byte, error)
	Decrypt(encryptedData []byte) ([]byte, error)
	EncryptString(data string) (string, error)
	DecryptString(encryptedData string) (string, error)
}

// KeyProvider interface for external key management
type KeyProvider interface {
	GetKey(keyID string) ([]byte, error)
	GetCurrentKeyID() string
	RotateKey() error
}

// FieldEncryptor provides field-level encryption utilities
type FieldEncryptor interface {
	EncryptField(fieldName string, data []byte) ([]byte, error)
	DecryptField(fieldName string, encryptedData []byte) ([]byte, error)
	EncryptPII(data *PIIData) (*EncryptedPIIData, error)
	DecryptPII(encryptedData *EncryptedPIIData) (*PIIData, error)
}

// PIIData represents personally identifiable information
type PIIData struct {
	FirstName string
	LastName  string
	Email     string
	Phone     string
	Address   string
}

// EncryptedPIIData represents encrypted PII data
type EncryptedPIIData struct {
	FirstNameEncrypted []byte
	LastNameEncrypted  []byte
	EmailEncrypted     []byte
	PhoneEncrypted     []byte
	AddressEncrypted   []byte
	KeyID              string
}

// AESGCMEncryptor implements AES-256-GCM encryption
type AESGCMEncryptor struct {
	key []byte
}

// NewAESGCMEncryptor creates a new AES-GCM encryptor
func NewAESGCMEncryptor(key []byte) (*AESGCMEncryptor, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256")
	}

	return &AESGCMEncryptor{
		key: key,
	}, nil
}

// Encrypt encrypts data using AES-256-GCM
func (e *AESGCMEncryptor) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypt decrypts data using AES-256-GCM
func (e *AESGCMEncryptor) Decrypt(encryptedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("encrypted data too short")
	}

	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// EncryptString encrypts a string and returns base64 encoded result
func (e *AESGCMEncryptor) EncryptString(data string) (string, error) {
	encrypted, err := e.Encrypt([]byte(data))
	if err != nil {
		return "", err
	}
	return encodeBase64(encrypted), nil
}

// DecryptString decrypts a base64 encoded string
func (e *AESGCMEncryptor) DecryptString(encryptedData string) (string, error) {
	decoded, err := decodeBase64(encryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	decrypted, err := e.Decrypt(decoded)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

// Base64 encoding/decoding utilities
func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func decodeBase64(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

// StaticKeyProvider provides a simple static key provider for development/testing
type StaticKeyProvider struct {
	keys      map[string][]byte
	currentID string
}

// NewStaticKeyProvider creates a new static key provider
func NewStaticKeyProvider(key []byte, keyID string) *StaticKeyProvider {
	return &StaticKeyProvider{
		keys: map[string][]byte{
			keyID: key,
		},
		currentID: keyID,
	}
}

// GetKey returns the key for the given key ID
func (p *StaticKeyProvider) GetKey(keyID string) ([]byte, error) {
	key, exists := p.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}
	return key, nil
}

// GetCurrentKeyID returns the current key ID
func (p *StaticKeyProvider) GetCurrentKeyID() string {
	return p.currentID
}

// RotateKey rotates to a new key (not implemented for static provider)
func (p *StaticKeyProvider) RotateKey() error {
	return fmt.Errorf("key rotation not supported by static key provider")
}

// PIIFieldEncryptor implements field-level encryption for PII data
type PIIFieldEncryptor struct {
	encryptor   Encryptor
	keyProvider KeyProvider
}

// NewPIIFieldEncryptor creates a new PII field encryptor
func NewPIIFieldEncryptor(encryptor Encryptor, keyProvider KeyProvider) *PIIFieldEncryptor {
	return &PIIFieldEncryptor{
		encryptor:   encryptor,
		keyProvider: keyProvider,
	}
}

// EncryptField encrypts a specific field
func (f *PIIFieldEncryptor) EncryptField(fieldName string, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	return f.encryptor.Encrypt(data)
}

// DecryptField decrypts a specific field
func (f *PIIFieldEncryptor) DecryptField(fieldName string, encryptedData []byte) ([]byte, error) {
	if len(encryptedData) == 0 {
		return nil, nil
	}
	return f.encryptor.Decrypt(encryptedData)
}

// EncryptPII encrypts all PII data fields
func (f *PIIFieldEncryptor) EncryptPII(data *PIIData) (*EncryptedPIIData, error) {
	if data == nil {
		return nil, fmt.Errorf("PII data cannot be nil")
	}

	result := &EncryptedPIIData{
		KeyID: f.keyProvider.GetCurrentKeyID(),
	}

	var err error

	// Encrypt each field if it's not empty
	if data.FirstName != "" {
		result.FirstNameEncrypted, err = f.EncryptField("first_name", []byte(data.FirstName))
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt first name: %w", err)
		}
	}

	if data.LastName != "" {
		result.LastNameEncrypted, err = f.EncryptField("last_name", []byte(data.LastName))
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt last name: %w", err)
		}
	}

	if data.Email != "" {
		result.EmailEncrypted, err = f.EncryptField("email", []byte(data.Email))
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt email: %w", err)
		}
	}

	if data.Phone != "" {
		result.PhoneEncrypted, err = f.EncryptField("phone", []byte(data.Phone))
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt phone: %w", err)
		}
	}

	if data.Address != "" {
		result.AddressEncrypted, err = f.EncryptField("address", []byte(data.Address))
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt address: %w", err)
		}
	}

	return result, nil
}

// DecryptPII decrypts all PII data fields
func (f *PIIFieldEncryptor) DecryptPII(encryptedData *EncryptedPIIData) (*PIIData, error) {
	if encryptedData == nil {
		return nil, fmt.Errorf("encrypted PII data cannot be nil")
	}

	result := &PIIData{}
	var err error

	// Decrypt each field if it's not empty
	if len(encryptedData.FirstNameEncrypted) > 0 {
		decrypted, err := f.DecryptField("first_name", encryptedData.FirstNameEncrypted)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt first name: %w", err)
		}
		result.FirstName = string(decrypted)
	}

	if len(encryptedData.LastNameEncrypted) > 0 {
		decrypted, err := f.DecryptField("last_name", encryptedData.LastNameEncrypted)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt last name: %w", err)
		}
		result.LastName = string(decrypted)
	}

	if len(encryptedData.EmailEncrypted) > 0 {
		decrypted, err := f.DecryptField("email", encryptedData.EmailEncrypted)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt email: %w", err)
		}
		result.Email = string(decrypted)
	}

	if len(encryptedData.PhoneEncrypted) > 0 {
		decrypted, err := f.DecryptField("phone", encryptedData.PhoneEncrypted)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt phone: %w", err)
		}
		result.Phone = string(decrypted)
	}

	if len(encryptedData.AddressEncrypted) > 0 {
		decrypted, err := f.DecryptField("address", encryptedData.AddressEncrypted)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt address: %w", err)
		}
		result.Address = string(decrypted)
	}

	return result, nil
}

// EncryptionService provides a high-level encryption service
type EncryptionService struct {
	encryptor      Encryptor
	fieldEncryptor FieldEncryptor
	keyProvider    KeyProvider
}

// NewEncryptionService creates a new encryption service
func NewEncryptionService(keyProvider KeyProvider) (*EncryptionService, error) {
	currentKeyID := keyProvider.GetCurrentKeyID()
	key, err := keyProvider.GetKey(currentKeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current key: %w", err)
	}

	encryptor, err := NewAESGCMEncryptor(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryptor: %w", err)
	}

	fieldEncryptor := NewPIIFieldEncryptor(encryptor, keyProvider)

	return &EncryptionService{
		encryptor:      encryptor,
		fieldEncryptor: fieldEncryptor,
		keyProvider:    keyProvider,
	}, nil
}

// GetEncryptor returns the underlying encryptor
func (s *EncryptionService) GetEncryptor() Encryptor {
	return s.encryptor
}

// GetFieldEncryptor returns the field encryptor
func (s *EncryptionService) GetFieldEncryptor() FieldEncryptor {
	return s.fieldEncryptor
}

// GetKeyProvider returns the key provider
func (s *EncryptionService) GetKeyProvider() KeyProvider {
	return s.keyProvider
}
