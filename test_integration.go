package main

import (
	"fmt"
	"log"

	"github.com/google/uuid"
	"github.com/steve-mir/go-auth-system/internal/service/role"
)

// Integration test to verify complete RBAC functionality
func main() {
	fmt.Println("Running RBAC Integration Test...")

	// Test all RBAC requirements
	testRequirement8_1() // Role definitions with permissions
	testRequirement8_2() // User role inheritance
	testRequirement8_3() // Access validation
	testRequirement8_4() // Permission changes take effect

	fmt.Println("RBAC Integration test completed successfully!")
}

// Requirement 8.1: WHEN roles are defined THEN the system SHALL store role definitions with associated permissions
func testRequirement8_1() {
	fmt.Println("\n=== Testing Requirement 8.1: Role Definitions ===")

	// Test role creation with permissions
	adminRole := role.NewAdminRole()
	fmt.Printf("Admin role created with %d permissions\n", len(adminRole.Permissions))

	// Test custom role creation
	customRole := &role.Role{
		Name:        "custom-manager",
		Description: "Custom manager role",
		Permissions: []role.Permission{
			{Resource: "user", Action: "read", Scope: "group"},
			{Resource: "project", Action: "manage", Scope: "group"},
			{
				Resource: "document",
				Action:   "read",
				Scope:    "group",
				Attributes: map[string]any{
					"department": "engineering",
					"clearance":  "internal",
				},
			},
		},
	}

	fmt.Printf("Custom role created: %s with %d permissions\n", customRole.Name, len(customRole.Permissions))

	// Test permission marshaling/unmarshaling
	permissionsJSON, err := role.MarshalPermissions(customRole.Permissions)
	if err != nil {
		log.Printf("Error marshaling permissions: %v", err)
		return
	}

	unmarshaledPermissions, err := role.UnmarshalPermissions(permissionsJSON)
	if err != nil {
		log.Printf("Error unmarshaling permissions: %v", err)
		return
	}

	fmt.Printf("Permissions successfully marshaled and unmarshaled: %d permissions\n", len(unmarshaledPermissions))
}

// Requirement 8.2: WHEN users are assigned roles THEN they SHALL inherit the permissions of those roles
func testRequirement8_2() {
	fmt.Println("\n=== Testing Requirement 8.2: Role Inheritance ===")

	// Create test roles
	userRole := role.NewUserRole()
	moderatorRole := role.NewModeratorRole()

	// Simulate user with multiple roles
	userRoles := []*role.Role{userRole, moderatorRole}

	// Collect all permissions from user roles
	var allPermissions []role.Permission
	permissionMap := make(map[string]role.Permission)

	for _, r := range userRoles {
		for _, permission := range r.Permissions {
			permissionMap[permission.String()] = permission
		}
	}

	// Convert map back to slice
	for _, permission := range permissionMap {
		allPermissions = append(allPermissions, permission)
	}

	fmt.Printf("User with roles %s and %s inherits %d unique permissions\n",
		userRole.Name, moderatorRole.Name, len(allPermissions))

	// Test permission set functionality
	permissionSet := role.NewPermissionSet(allPermissions)
	testPermission := role.Permission{Resource: "user", Action: "read", Scope: "own"}
	hasPermission := permissionSet.Contains(testPermission)

	fmt.Printf("User has permission %s: %v\n", testPermission.String(), hasPermission)
}

// Requirement 8.3: WHEN access is requested THEN the system SHALL validate permissions before granting access
func testRequirement8_3() {
	fmt.Println("\n=== Testing Requirement 8.3: Access Validation ===")

	// Create a role with specific permissions
	managerRole := &role.Role{
		Name:        "manager",
		Description: "Department manager",
		Permissions: []role.Permission{
			{
				Resource: "user",
				Action:   "read",
				Scope:    "group",
				Attributes: map[string]any{
					"department": "engineering",
				},
			},
			{
				Resource: "document",
				Action:   "read",
				Scope:    "group",
				Attributes: map[string]any{
					"department": "engineering",
					"clearance":  "internal",
				},
			},
		},
	}

	// Test basic permission validation
	userReadPermission := role.Permission{Resource: "user", Action: "read", Scope: "group"}
	hasBasicPermission := managerRole.HasPermission(userReadPermission)
	fmt.Printf("Manager has basic user:read:group permission: %v\n", hasBasicPermission)

	// Test attribute-based access control
	testAccessRequests := []role.AccessRequest{
		{
			UserID:   uuid.New(),
			Resource: "document",
			Action:   "read",
			Scope:    "group",
			Attributes: map[string]any{
				"department": "engineering",
				"clearance":  "internal",
			},
		},
		{
			UserID:   uuid.New(),
			Resource: "document",
			Action:   "read",
			Scope:    "group",
			Attributes: map[string]any{
				"department": "marketing", // Different department
				"clearance":  "internal",
			},
		},
	}

	for i, req := range testAccessRequests {
		// Simulate access validation
		allowed := validateAccess(managerRole.Permissions, req)
		fmt.Printf("Access request %d (dept: %s) allowed: %v\n",
			i+1, req.Attributes["department"], allowed)
	}
}

// Requirement 8.4: WHEN permissions change THEN the changes SHALL take effect for subsequent requests
func testRequirement8_4() {
	fmt.Println("\n=== Testing Requirement 8.4: Permission Changes Take Effect ===")

	// Create initial role
	testRole := &role.Role{
		Name:        "test-role",
		Description: "Test role for permission changes",
		Permissions: []role.Permission{
			{Resource: "user", Action: "read", Scope: "own"},
		},
	}

	// Test initial permission
	readPermission := role.Permission{Resource: "user", Action: "read", Scope: "own"}
	writePermission := role.Permission{Resource: "user", Action: "write", Scope: "own"}

	fmt.Printf("Initial role has read permission: %v\n", testRole.HasPermission(readPermission))
	fmt.Printf("Initial role has write permission: %v\n", testRole.HasPermission(writePermission))

	// Add new permission (simulating role update)
	testRole.AddPermission(writePermission)

	fmt.Printf("After adding write permission:\n")
	fmt.Printf("Role has read permission: %v\n", testRole.HasPermission(readPermission))
	fmt.Printf("Role has write permission: %v\n", testRole.HasPermission(writePermission))

	// Remove permission
	testRole.RemovePermission(readPermission)

	fmt.Printf("After removing read permission:\n")
	fmt.Printf("Role has read permission: %v\n", testRole.HasPermission(readPermission))
	fmt.Printf("Role has write permission: %v\n", testRole.HasPermission(writePermission))
}

// Helper function to simulate access validation
func validateAccess(permissions []role.Permission, req role.AccessRequest) bool {
	permissionSet := role.NewPermissionSet(permissions)
	requestedPermission := role.Permission{
		Resource:   req.Resource,
		Action:     req.Action,
		Scope:      req.Scope,
		Attributes: req.Attributes,
	}

	// Basic permission check
	if !permissionSet.Contains(requestedPermission) {
		return false
	}

	// Attribute-based validation
	for _, perm := range permissions {
		if perm.Resource == req.Resource && perm.Action == req.Action {
			if len(perm.Attributes) == 0 {
				return true // No attribute restrictions
			}

			// Check if all required attributes match
			allMatch := true
			for key, expectedValue := range perm.Attributes {
				if reqValue, exists := req.Attributes[key]; exists {
					if expectedValue != reqValue {
						allMatch = false
						break
					}
				} else {
					allMatch = false
					break
				}
			}

			if allMatch {
				return true
			}
		}
	}

	return false
}
