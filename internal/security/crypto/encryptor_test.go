package crypto

import (
	"crypto/rand"
	"testing"
)

func TestAESGCMEncryptor_NewAESGCMEncryptor(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
		wantErr bool
	}{
		{
			name:    "valid 32-byte key",
			keySize: 32,
			wantErr: false,
		},
		{
			name:    "invalid 16-byte key",
			keySize: 16,
			wantErr: true,
		},
		{
			name:    "invalid 24-byte key",
			keySize: 24,
			wantErr: true,
		},
		{
			name:    "invalid empty key",
			keySize: 0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			if tt.keySize > 0 {
				rand.Read(key)
			}

			encryptor, err := NewAESGCMEncryptor(key)
			if tt.wantErr {
				if err == nil {
					t.Errorf("NewAESGCMEncryptor() expected error but got none")
				}
				if encryptor != nil {
					t.Errorf("NewAESGCMEncryptor() expected nil encryptor but got %v", encryptor)
				}
			} else {
				if err != nil {
					t.Errorf("NewAESGCMEncryptor() unexpected error: %v", err)
				}
				if encryptor == nil {
					t.Errorf("NewAESGCMEncryptor() expected encryptor but got nil")
				}
			}
		})
	}
}

func TestAESGCMEncryptor_EncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	encryptor, err := NewAESGCMEncryptor(key)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "simple text",
			data: []byte("Hello, World!"),
		},
		{
			name: "empty data",
			data: []byte(""),
		},
		{
			name: "binary data",
			data: []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD},
		},
		{
			name: "large data",
			data: make([]byte, 1024),
		},
		{
			name: "unicode text",
			data: []byte("Hello, 世界! 🌍"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill large data with random bytes
			if len(tt.data) == 1024 {
				rand.Read(tt.data)
			}

			// Encrypt
			encrypted, err := encryptor.Encrypt(tt.data)
			if err != nil {
				t.Fatalf("Encrypt() error: %v", err)
			}

			// Verify encrypted data is different from original (unless empty)
			if len(tt.data) > 0 && string(encrypted) == string(tt.data) {
				t.Error("Encrypted data should be different from original")
			}

			// Decrypt
			decrypted, err := encryptor.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decrypt() error: %v", err)
			}

			// Verify decrypted data matches original
			if string(decrypted) != string(tt.data) {
				t.Errorf("Decrypted data doesn't match original. Got %v, want %v", decrypted, tt.data)
			}
		})
	}
}

func TestAESGCMEncryptor_EncryptStringDecryptString(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	encryptor, err := NewAESGCMEncryptor(key)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	tests := []string{
		"Hello, World!",
		"",
		"Unicode: 世界 🌍",
		"Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?",
		"Multi-line\ntext\nwith\nnewlines",
	}

	for _, testData := range tests {
		t.Run(testData, func(t *testing.T) {
			// Encrypt
			encrypted, err := encryptor.EncryptString(testData)
			if err != nil {
				t.Fatalf("EncryptString() error: %v", err)
			}

			// Verify encrypted string is different from original (unless empty)
			if len(testData) > 0 && encrypted == testData {
				t.Error("Encrypted string should be different from original")
			}

			// Decrypt
			decrypted, err := encryptor.DecryptString(encrypted)
			if err != nil {
				t.Fatalf("DecryptString() error: %v", err)
			}

			// Verify decrypted string matches original
			if decrypted != testData {
				t.Errorf("Decrypted string doesn't match original. Got %q, want %q", decrypted, testData)
			}
		})
	}
}

func TestAESGCMEncryptor_DecryptInvalidData(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	encryptor, err := NewAESGCMEncryptor(key)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "too short data",
			data: []byte{0x01, 0x02},
		},
		{
			name: "corrupted data",
			data: make([]byte, 32), // Random data that's not properly encrypted
		},
		{
			name: "empty data",
			data: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "corrupted data" {
				rand.Read(tt.data)
			}

			_, err := encryptor.Decrypt(tt.data)
			if err == nil {
				t.Error("Decrypt() expected error but got none")
			}
		})
	}
}

func TestStaticKeyProvider(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	keyID := "test-key-1"

	provider := NewStaticKeyProvider(key, keyID)

	// Test GetCurrentKeyID
	currentID := provider.GetCurrentKeyID()
	if currentID != keyID {
		t.Errorf("GetCurrentKeyID() = %v, want %v", currentID, keyID)
	}

	// Test GetKey with valid key ID
	retrievedKey, err := provider.GetKey(keyID)
	if err != nil {
		t.Errorf("GetKey() error: %v", err)
	}
	if string(retrievedKey) != string(key) {
		t.Errorf("GetKey() returned wrong key")
	}

	// Test GetKey with invalid key ID
	_, err = provider.GetKey("invalid-key")
	if err == nil {
		t.Error("GetKey() with invalid key ID should return error")
	}

	// Test RotateKey (should fail for static provider)
	err = provider.RotateKey()
	if err == nil {
		t.Error("RotateKey() should return error for static provider")
	}
}

func TestPIIFieldEncryptor_EncryptDecryptPII(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	keyID := "test-key"

	encryptor, err := NewAESGCMEncryptor(key)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	keyProvider := NewStaticKeyProvider(key, keyID)
	fieldEncryptor := NewPIIFieldEncryptor(encryptor, keyProvider)

	tests := []struct {
		name string
		data *PIIData
	}{
		{
			name: "complete PII data",
			data: &PIIData{
				FirstName: "John",
				LastName:  "Doe",
				Email:     "john.doe@example.com",
				Phone:     "+1234567890",
				Address:   "123 Main St, City, State 12345",
			},
		},
		{
			name: "partial PII data",
			data: &PIIData{
				FirstName: "Jane",
				Email:     "jane@example.com",
			},
		},
		{
			name: "empty PII data",
			data: &PIIData{},
		},
		{
			name: "unicode PII data",
			data: &PIIData{
				FirstName: "José",
				LastName:  "García",
				Email:     "jose.garcia@ejemplo.com",
				Address:   "Calle Principal 123, Ciudad",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt PII
			encrypted, err := fieldEncryptor.EncryptPII(tt.data)
			if err != nil {
				t.Fatalf("EncryptPII() error: %v", err)
			}

			// Verify key ID is set
			if encrypted.KeyID != keyID {
				t.Errorf("EncryptPII() KeyID = %v, want %v", encrypted.KeyID, keyID)
			}

			// Decrypt PII
			decrypted, err := fieldEncryptor.DecryptPII(encrypted)
			if err != nil {
				t.Fatalf("DecryptPII() error: %v", err)
			}

			// Verify all fields match
			if decrypted.FirstName != tt.data.FirstName {
				t.Errorf("FirstName mismatch: got %v, want %v", decrypted.FirstName, tt.data.FirstName)
			}
			if decrypted.LastName != tt.data.LastName {
				t.Errorf("LastName mismatch: got %v, want %v", decrypted.LastName, tt.data.LastName)
			}
			if decrypted.Email != tt.data.Email {
				t.Errorf("Email mismatch: got %v, want %v", decrypted.Email, tt.data.Email)
			}
			if decrypted.Phone != tt.data.Phone {
				t.Errorf("Phone mismatch: got %v, want %v", decrypted.Phone, tt.data.Phone)
			}
			if decrypted.Address != tt.data.Address {
				t.Errorf("Address mismatch: got %v, want %v", decrypted.Address, tt.data.Address)
			}
		})
	}
}

func TestPIIFieldEncryptor_EncryptDecryptField(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	encryptor, err := NewAESGCMEncryptor(key)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	keyProvider := NewStaticKeyProvider(key, "test-key")
	fieldEncryptor := NewPIIFieldEncryptor(encryptor, keyProvider)

	tests := []struct {
		name      string
		fieldName string
		data      []byte
	}{
		{
			name:      "non-empty field",
			fieldName: "test_field",
			data:      []byte("test data"),
		},
		{
			name:      "empty field",
			fieldName: "empty_field",
			data:      []byte(""),
		},
		{
			name:      "nil field",
			fieldName: "nil_field",
			data:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt field
			encrypted, err := fieldEncryptor.EncryptField(tt.fieldName, tt.data)
			if err != nil {
				t.Fatalf("EncryptField() error: %v", err)
			}

			// For empty/nil data, encrypted should also be nil
			if len(tt.data) == 0 {
				if encrypted != nil {
					t.Errorf("EncryptField() with empty data should return nil, got %v", encrypted)
				}
				return
			}

			// Decrypt field
			decrypted, err := fieldEncryptor.DecryptField(tt.fieldName, encrypted)
			if err != nil {
				t.Fatalf("DecryptField() error: %v", err)
			}

			// Verify decrypted data matches original
			if string(decrypted) != string(tt.data) {
				t.Errorf("DecryptField() mismatch: got %v, want %v", decrypted, tt.data)
			}
		})
	}
}

func TestPIIFieldEncryptor_ErrorCases(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	encryptor, err := NewAESGCMEncryptor(key)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	keyProvider := NewStaticKeyProvider(key, "test-key")
	fieldEncryptor := NewPIIFieldEncryptor(encryptor, keyProvider)

	// Test EncryptPII with nil data
	_, err = fieldEncryptor.EncryptPII(nil)
	if err == nil {
		t.Error("EncryptPII() with nil data should return error")
	}

	// Test DecryptPII with nil data
	_, err = fieldEncryptor.DecryptPII(nil)
	if err == nil {
		t.Error("DecryptPII() with nil data should return error")
	}
}

func TestEncryptionService(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	keyID := "test-key"

	keyProvider := NewStaticKeyProvider(key, keyID)

	// Test NewEncryptionService
	service, err := NewEncryptionService(keyProvider)
	if err != nil {
		t.Fatalf("NewEncryptionService() error: %v", err)
	}

	// Test GetEncryptor
	encryptor := service.GetEncryptor()
	if encryptor == nil {
		t.Error("GetEncryptor() returned nil")
	}

	// Test GetFieldEncryptor
	fieldEncryptor := service.GetFieldEncryptor()
	if fieldEncryptor == nil {
		t.Error("GetFieldEncryptor() returned nil")
	}

	// Test GetKeyProvider
	returnedKeyProvider := service.GetKeyProvider()
	if returnedKeyProvider == nil {
		t.Error("GetKeyProvider() returned nil")
	}

	// Test that the service components work together
	testData := "test encryption service"
	encrypted, err := encryptor.EncryptString(testData)
	if err != nil {
		t.Fatalf("EncryptString() error: %v", err)
	}

	decrypted, err := encryptor.DecryptString(encrypted)
	if err != nil {
		t.Fatalf("DecryptString() error: %v", err)
	}

	if decrypted != testData {
		t.Errorf("Service encryption/decryption failed: got %v, want %v", decrypted, testData)
	}
}

func TestEncryptionService_InvalidKeyProvider(t *testing.T) {
	// Create a key provider that will fail
	keyProvider := &StaticKeyProvider{
		keys:      make(map[string][]byte),
		currentID: "nonexistent-key",
	}

	_, err := NewEncryptionService(keyProvider)
	if err == nil {
		t.Error("NewEncryptionService() with invalid key provider should return error")
	}
}

// Benchmark tests
func BenchmarkAESGCMEncryptor_Encrypt(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)

	encryptor, err := NewAESGCMEncryptor(key)
	if err != nil {
		b.Fatalf("Failed to create encryptor: %v", err)
	}

	data := []byte("This is test data for benchmarking encryption performance")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := encryptor.Encrypt(data)
		if err != nil {
			b.Fatalf("Encrypt() error: %v", err)
		}
	}
}

func BenchmarkAESGCMEncryptor_Decrypt(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)

	encryptor, err := NewAESGCMEncryptor(key)
	if err != nil {
		b.Fatalf("Failed to create encryptor: %v", err)
	}

	data := []byte("This is test data for benchmarking decryption performance")
	encrypted, err := encryptor.Encrypt(data)
	if err != nil {
		b.Fatalf("Failed to encrypt test data: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := encryptor.Decrypt(encrypted)
		if err != nil {
			b.Fatalf("Decrypt() error: %v", err)
		}
	}
}

func BenchmarkPIIFieldEncryptor_EncryptPII(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)

	encryptor, err := NewAESGCMEncryptor(key)
	if err != nil {
		b.Fatalf("Failed to create encryptor: %v", err)
	}

	keyProvider := NewStaticKeyProvider(key, "test-key")
	fieldEncryptor := NewPIIFieldEncryptor(encryptor, keyProvider)

	piiData := &PIIData{
		FirstName: "John",
		LastName:  "Doe",
		Email:     "john.doe@example.com",
		Phone:     "+1234567890",
		Address:   "123 Main St, City, State 12345",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := fieldEncryptor.EncryptPII(piiData)
		if err != nil {
			b.Fatalf("EncryptPII() error: %v", err)
		}
	}
}
