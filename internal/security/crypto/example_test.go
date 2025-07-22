package crypto

import (
	"crypto/rand"
	"fmt"
	"log"
)

// ExampleEncryptionService demonstrates how to use the encryption service
func ExampleEncryptionService() {
	// Generate a 32-byte key for AES-256
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}

	// Create a key provider
	keyProvider := NewStaticKeyProvider(key, "example-key-1")

	// Create the encryption service
	service, err := NewEncryptionService(keyProvider)
	if err != nil {
		log.Fatal(err)
	}

	// Get the encryptor for general encryption
	encryptor := service.GetEncryptor()

	// Encrypt a simple string
	plaintext := "This is sensitive data"
	encrypted, err := encryptor.EncryptString(plaintext)
	if err != nil {
		log.Fatal(err)
	}

	// Decrypt the string
	decrypted, err := encryptor.DecryptString(encrypted)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Original: %s\n", plaintext)
	fmt.Printf("Decrypted: %s\n", decrypted)
	fmt.Printf("Match: %t\n", plaintext == decrypted)

	// Output:
	// Original: This is sensitive data
	// Decrypted: This is sensitive data
	// Match: true
}

// ExamplePIIFieldEncryptor demonstrates PII encryption
func ExamplePIIFieldEncryptor() {
	// Generate a 32-byte key for AES-256
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}

	// Create a key provider
	keyProvider := NewStaticKeyProvider(key, "pii-key-1")

	// Create the encryption service
	service, err := NewEncryptionService(keyProvider)
	if err != nil {
		log.Fatal(err)
	}

	// Get the field encryptor for PII data
	fieldEncryptor := service.GetFieldEncryptor()

	// Create PII data
	piiData := &PIIData{
		FirstName: "John",
		LastName:  "Doe",
		Email:     "john.doe@example.com",
		Phone:     "+1-555-123-4567",
		Address:   "123 Main St, Anytown, ST 12345",
	}

	// Encrypt PII data
	encryptedPII, err := fieldEncryptor.EncryptPII(piiData)
	if err != nil {
		log.Fatal(err)
	}

	// Decrypt PII data
	decryptedPII, err := fieldEncryptor.DecryptPII(encryptedPII)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Original First Name: %s\n", piiData.FirstName)
	fmt.Printf("Decrypted First Name: %s\n", decryptedPII.FirstName)
	fmt.Printf("Original Email: %s\n", piiData.Email)
	fmt.Printf("Decrypted Email: %s\n", decryptedPII.Email)
	fmt.Printf("Key ID: %s\n", encryptedPII.KeyID)

	// Output:
	// Original First Name: John
	// Decrypted First Name: John
	// Original Email: john.doe@example.com
	// Decrypted Email: john.doe@example.com
	// Key ID: pii-key-1
}

// ExampleAESGCMEncryptor demonstrates basic AES-GCM encryption
func ExampleAESGCMEncryptor() {
	// Generate a 32-byte key for AES-256
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}

	// Create encryptor
	encryptor, err := NewAESGCMEncryptor(key)
	if err != nil {
		log.Fatal(err)
	}

	// Encrypt binary data
	data := []byte("Sensitive binary data")
	encrypted, err := encryptor.Encrypt(data)
	if err != nil {
		log.Fatal(err)
	}

	// Decrypt binary data
	decrypted, err := encryptor.Decrypt(encrypted)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Original length: %d bytes\n", len(data))
	fmt.Printf("Encrypted length: %d bytes\n", len(encrypted))
	fmt.Printf("Decrypted length: %d bytes\n", len(decrypted))
	fmt.Printf("Data matches: %t\n", string(data) == string(decrypted))

	// Output:
	// Original length: 20 bytes
	// Encrypted length: 36 bytes
	// Decrypted length: 20 bytes
	// Data matches: true
}
