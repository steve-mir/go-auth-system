package hash_test

import (
	"context"
	"fmt"
	"log"

	"github.com/steve-mir/go-auth-system/internal/config"
	"github.com/steve-mir/go-auth-system/internal/security/hash"
)

func ExampleFactory_CreateHashService_argon2() {
	// Configure Argon2 hashing
	cfg := config.PasswordHashConfig{
		Algorithm: "argon2",
		Argon2: config.Argon2Config{
			Memory:      64 * 1024, // 64 MB
			Iterations:  3,
			Parallelism: 2,
			SaltLength:  16,
			KeyLength:   32,
		},
	}

	// Create factory and hash service
	factory := hash.NewFactory(cfg)
	service, err := factory.CreateHashService()
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	password := "mySecurePassword123"

	// Hash the password
	hashedPassword, err := service.HashPassword(ctx, password)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Algorithm: %s\n", factory.GetAlgorithm())
	fmt.Printf("Hash starts with: $argon2id$\n")

	// Verify the password
	err = service.VerifyPassword(ctx, password, hashedPassword)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Password verified successfully")

	// Check if rehash is needed
	needsRehash := service.NeedsRehash(ctx, hashedPassword)
	fmt.Printf("Needs rehash: %v\n", needsRehash)

	// Output:
	// Algorithm: argon2
	// Hash starts with: $argon2id$
	// Password verified successfully
	// Needs rehash: false
}

func ExampleFactory_CreateHashService_bcrypt() {
	// Configure bcrypt hashing
	cfg := config.PasswordHashConfig{
		Algorithm: "bcrypt",
		Bcrypt: config.BcryptConfig{
			Cost: 12,
		},
	}

	// Create factory and hash service
	factory := hash.NewFactory(cfg)
	service, err := factory.CreateHashService()
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	password := "mySecurePassword123"

	// Hash the password
	hashedPassword, err := service.HashPassword(ctx, password)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Algorithm: %s\n", factory.GetAlgorithm())
	fmt.Printf("Hash starts with: $2a$12$\n")

	// Verify the password
	err = service.VerifyPassword(ctx, password, hashedPassword)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Password verified successfully")

	// Check if rehash is needed
	needsRehash := service.NeedsRehash(ctx, hashedPassword)
	fmt.Printf("Needs rehash: %v\n", needsRehash)

	// Output:
	// Algorithm: bcrypt
	// Hash starts with: $2a$12$
	// Password verified successfully
	// Needs rehash: false
}

func ExampleFactory_GetRecommendedConfig() {
	// Get recommended configuration for Argon2
	factory := hash.NewFactory(config.PasswordHashConfig{Algorithm: "argon2"})
	recommended := factory.GetRecommendedConfig()

	fmt.Printf("Recommended algorithm: %s\n", recommended.Algorithm)
	fmt.Printf("Recommended Argon2 memory: %d KB\n", recommended.Argon2.Memory)
	fmt.Printf("Recommended Argon2 iterations: %d\n", recommended.Argon2.Iterations)

	// Output:
	// Recommended algorithm: argon2
	// Recommended Argon2 memory: 65536 KB
	// Recommended Argon2 iterations: 3
}
