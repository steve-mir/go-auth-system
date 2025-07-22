package main

import (
	"fmt"

	"github.com/steve-mir/go-auth-system/internal/service/role"
)

// Simple test to verify role implementation
func main() {
	fmt.Println("Testing Role-Based Access Control Implementation...")

	// Test permission creation and validation
	testPermissions()

	// Test role templates
	testRoleTemplates()

	fmt.Println("Role implementation test completed successfully!")
}

func testPermissions() {
	fmt.Println("\n=== Testing Permission System ===")

	// Test permission string representation
	perm := role.Permission{
		Resource: "user",
		Action:   "read",
		Scope:    "own",
	}

	fmt.Printf("Permission string: %s\n", perm.String())

	// Test permission set
	permissions := []role.Permission{
		{Resource: "user", Action: "read"},
		{Resource: "user", Action: "write"},
		{Resource: "role", Action: "manage"},
	}

	permSet := role.NewPermissionSet(permissions)

	// Test contains functionality
	testPerm := role.Permission{Resource: "user", Action: "read"}
	fmt.Printf("Permission set contains %s: %v\n", testPerm.String(), permSet.Contains(testPerm))

	// Test wildcard matching
	wildcardPerm := role.Permission{Resource: "user", Action: "delete"}
	fmt.Printf("Permission set contains %s (wildcard): %v\n", wildcardPerm.String(), permSet.Contains(wildcardPerm))
}

func testRoleTemplates() {
	fmt.Println("\n=== Testing Role Templates ===")

	// Test predefined roles
	roles := map[string]func() *role.Role{
		"guest":     role.NewGuestRole,
		"user":      role.NewUserRole,
		"moderator": role.NewModeratorRole,
		"admin":     role.NewAdminRole,
		"superuser": role.NewSuperUserRole,
	}

	for name, roleFunc := range roles {
		r := roleFunc()
		fmt.Printf("Role '%s': %s (%d permissions)\n", name, r.Description, len(r.Permissions))

		// Test role methods
		testPerm := role.Permission{Resource: "user", Action: "read", Scope: "own"}
		fmt.Printf("  - Has permission %s: %v\n", testPerm.String(), r.HasPermission(testPerm))
	}
}
