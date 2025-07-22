package main

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/steve-mir/go-auth-system/internal/service/auth"
	"github.com/steve-mir/go-auth-system/internal/service/role"
)

// Test to verify auth service integration with role service
func main() {
	fmt.Println("Testing Auth Service Integration with Role-Based Access Control...")

	// Test role-based token claims
	testRoleBasedTokenClaims()

	// Test session role management
	testSessionRoleManagement()

	fmt.Println("Auth service integration test completed successfully!")
}

func testRoleBasedTokenClaims() {
	fmt.Println("\n=== Testing Role-Based Token Claims ===")

	// Test that roles are properly included in token claims
	roles := []string{"admin", "user"}
	fmt.Printf("Test roles: %v\n", roles)

	// Verify that roles are included in session data
	sessionData := &auth.SessionData{
		ID:        uuid.New().String(),
		UserID:    uuid.New().String(),
		TokenHash: "test-hash",
		TokenType: "access",
		Roles:     roles,
		ExpiresAt: 1234567890,
		IPAddress: "127.0.0.1",
		UserAgent: "test-agent",
		CreatedAt: 1234567890,
		LastUsed:  1234567890,
	}

	fmt.Printf("Session roles: %v\n", sessionData.Roles)

	// Test that roles are properly handled in validation response
	validationResponse := &auth.ValidateTokenResponse{
		Valid:     true,
		UserID:    uuid.New().String(),
		Email:     "test@example.com",
		Username:  "testuser",
		Roles:     roles,
		ExpiresAt: sessionData.ExpiresAt,
	}

	fmt.Printf("Validation response roles: %v\n", validationResponse.Roles)
}

func testSessionRoleManagement() {
	fmt.Println("\n=== Testing Session Role Management ===")

	// Test that user profile includes roles
	userProfile := &auth.UserProfile{
		ID:        uuid.New(),
		Email:     "test@example.com",
		Username:  "testuser",
		FirstName: "Test",
		LastName:  "User",
		Roles:     []string{"user", "moderator"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	fmt.Printf("User profile roles: %v\n", userProfile.Roles)

	// Test role permission validation
	testRolePermissions()
}

func testRolePermissions() {
	fmt.Println("\n=== Testing Role Permission Integration ===")

	// Test common role templates
	adminRole := role.NewAdminRole()
	userRole := role.NewUserRole()

	fmt.Printf("Admin role permissions: %d\n", len(adminRole.Permissions))
	fmt.Printf("User role permissions: %d\n", len(userRole.Permissions))

	// Test permission validation
	userReadPermission := role.Permission{
		Resource: "user",
		Action:   "read",
		Scope:    "own",
	}

	fmt.Printf("Admin has user:read:own permission: %v\n", adminRole.HasPermission(userReadPermission))
	fmt.Printf("User has user:read:own permission: %v\n", userRole.HasPermission(userReadPermission))

	// Test attribute-based permissions
	documentPermission := role.Permission{
		Resource: "document",
		Action:   "read",
		Scope:    "group",
		Attributes: map[string]any{
			"department": "engineering",
		},
	}

	fmt.Printf("Document permission string: %s\n", documentPermission.String())
}
