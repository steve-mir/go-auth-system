package hash

import (
	"context"
	"testing"

	"github.com/steve-mir/go-auth-system/internal/config"
)

// TestCrossAlgorithmCompatibility tests that different algorithms can coexist
func TestCrossAlgorithmCompatibility(t *testing.T) {
	ctx := context.Background()
	password := "testpassword123"

	// Create Argon2 service
	argon2Config := config.PasswordHashConfig{
		Algorithm: "argon2",
		Argon2: config.Argon2Config{
			Memory:      64 * 1024,
			Iterations:  3,
			Parallelism: 2,
			SaltLength:  16,
			KeyLength:   32,
		},
	}
	argon2Factory := NewFactory(argon2Config)
	argon2Service, err := argon2Factory.CreateHashService()
	if err != nil {
		t.Fatalf("failed to create Argon2 service: %v", err)
	}

	// Create bcrypt service
	bcryptConfig := config.PasswordHashConfig{
		Algorithm: "bcrypt",
		Bcrypt: config.BcryptConfig{
			Cost: 12,
		},
	}
	bcryptFactory := NewFactory(bcryptConfig)
	bcryptService, err := bcryptFactory.CreateHashService()
	if err != nil {
		t.Fatalf("failed to create bcrypt service: %v", err)
	}

	// Hash password with both services
	argon2Hash, err := argon2Service.HashPassword(ctx, password)
	if err != nil {
		t.Fatalf("failed to hash with Argon2: %v", err)
	}

	bcryptHash, err := bcryptService.HashPassword(ctx, password)
	if err != nil {
		t.Fatalf("failed to hash with bcrypt: %v", err)
	}

	// Verify that hashes are different
	if argon2Hash == bcryptHash {
		t.Error("different algorithms should produce different hashes")
	}

	// Verify that each service can verify its own hash
	if err := argon2Service.VerifyPassword(ctx, password, argon2Hash); err != nil {
		t.Errorf("Argon2 service should verify its own hash: %v", err)
	}

	if err := bcryptService.VerifyPassword(ctx, password, bcryptHash); err != nil {
		t.Errorf("bcrypt service should verify its own hash: %v", err)
	}

	// Verify that services cannot verify other algorithm's hashes
	if err := argon2Service.VerifyPassword(ctx, password, bcryptHash); err == nil {
		t.Error("Argon2 service should not verify bcrypt hash")
	}

	if err := bcryptService.VerifyPassword(ctx, password, argon2Hash); err == nil {
		t.Error("bcrypt service should not verify Argon2 hash")
	}
}

// TestPasswordMigrationScenario tests a realistic password migration scenario
func TestPasswordMigrationScenario(t *testing.T) {
	ctx := context.Background()
	password := "userpassword123"

	// Simulate existing bcrypt hashes (old system)
	oldConfig := config.PasswordHashConfig{
		Algorithm: "bcrypt",
		Bcrypt:    config.BcryptConfig{Cost: 10},
	}
	oldFactory := NewFactory(oldConfig)
	oldService, err := oldFactory.CreateHashService()
	if err != nil {
		t.Fatalf("failed to create old service: %v", err)
	}

	// Create old hash
	oldHash, err := oldService.HashPassword(ctx, password)
	if err != nil {
		t.Fatalf("failed to create old hash: %v", err)
	}

	// Simulate new system configuration (Argon2)
	newConfig := config.PasswordHashConfig{
		Algorithm: "argon2",
		Argon2: config.Argon2Config{
			Memory:      64 * 1024,
			Iterations:  3,
			Parallelism: 2,
			SaltLength:  16,
			KeyLength:   32,
		},
	}
	newFactory := NewFactory(newConfig)
	newService, err := newFactory.CreateHashService()
	if err != nil {
		t.Fatalf("failed to create new service: %v", err)
	}

	// Migration scenario: user logs in with old hash
	// 1. Verify password with old service
	if err := oldService.VerifyPassword(ctx, password, oldHash); err != nil {
		t.Fatalf("old service should verify old hash: %v", err)
	}

	// 2. Check if rehash is needed (should be true for different algorithm)
	if !newService.NeedsRehash(ctx, oldHash) {
		t.Error("new service should indicate old hash needs rehashing")
	}

	// 3. Create new hash with new service
	newHash, err := newService.HashPassword(ctx, password)
	if err != nil {
		t.Fatalf("failed to create new hash: %v", err)
	}

	// 4. Verify new hash works
	if err := newService.VerifyPassword(ctx, password, newHash); err != nil {
		t.Errorf("new service should verify new hash: %v", err)
	}

	// 5. Verify new hash doesn't need rehashing
	if newService.NeedsRehash(ctx, newHash) {
		t.Error("new hash should not need rehashing")
	}
}

// TestConfigurationUpgrade tests upgrading algorithm parameters
func TestConfigurationUpgrade(t *testing.T) {
	ctx := context.Background()
	password := "upgradetest123"

	// Old bcrypt configuration (lower cost)
	oldConfig := config.PasswordHashConfig{
		Algorithm: "bcrypt",
		Bcrypt:    config.BcryptConfig{Cost: 10},
	}
	oldFactory := NewFactory(oldConfig)
	oldService, err := oldFactory.CreateHashService()
	if err != nil {
		t.Fatalf("failed to create old service: %v", err)
	}

	// Create hash with old configuration
	oldHash, err := oldService.HashPassword(ctx, password)
	if err != nil {
		t.Fatalf("failed to create old hash: %v", err)
	}

	// New bcrypt configuration (higher cost)
	newConfig := config.PasswordHashConfig{
		Algorithm: "bcrypt",
		Bcrypt:    config.BcryptConfig{Cost: 12},
	}
	newFactory := NewFactory(newConfig)
	newService, err := newFactory.CreateHashService()
	if err != nil {
		t.Fatalf("failed to create new service: %v", err)
	}

	// Old hash should need rehashing
	if !newService.NeedsRehash(ctx, oldHash) {
		t.Error("old hash should need rehashing with new parameters")
	}

	// Old hash should still verify with new service
	if err := newService.VerifyPassword(ctx, password, oldHash); err != nil {
		t.Errorf("new service should still verify old hash: %v", err)
	}

	// Create new hash with upgraded parameters
	newHash, err := newService.HashPassword(ctx, password)
	if err != nil {
		t.Fatalf("failed to create new hash: %v", err)
	}

	// New hash should not need rehashing
	if newService.NeedsRehash(ctx, newHash) {
		t.Error("new hash should not need rehashing")
	}

	// Both hashes should verify the same password
	if err := newService.VerifyPassword(ctx, password, oldHash); err != nil {
		t.Errorf("should verify old hash: %v", err)
	}
	if err := newService.VerifyPassword(ctx, password, newHash); err != nil {
		t.Errorf("should verify new hash: %v", err)
	}
}
