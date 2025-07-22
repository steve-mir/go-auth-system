package role

import (
	"context"
	"fmt"
	"log"

	"github.com/google/uuid"
)

// ExampleUsage demonstrates how to use the role service
func ExampleUsage(service Service) {
	// This is a demonstration of how to use the role service
	// The service should be properly initialized with a real repository
	ctx := context.Background()

	// Example 1: Create a new role
	fmt.Println("=== Creating a new role ===")
	adminRole, err := service.CreateRole(ctx, CreateRoleRequest{
		Name:        "admin",
		Description: "System administrator with full access",
		Permissions: []Permission{
			PermUserManageAll,
			PermRoleManage,
			PermSystemManage,
			PermAuditRead,
		},
	})
	if err != nil {
		log.Printf("Error creating role: %v", err)
		return
	}
	fmt.Printf("Created role: %s (ID: %s)\n", adminRole.Name, adminRole.ID)

	// Example 2: Create a user role
	fmt.Println("\n=== Creating a user role ===")
	userRole, err := service.CreateRole(ctx, CreateRoleRequest{
		Name:        "user",
		Description: "Regular user with limited access",
		Permissions: []Permission{
			PermUserReadOwn,
			PermUserUpdateOwn,
		},
	})
	if err != nil {
		log.Printf("Error creating user role: %v", err)
		return
	}
	fmt.Printf("Created role: %s (ID: %s)\n", userRole.Name, userRole.ID)

	// Example 3: Create a role with attribute-based permissions
	fmt.Println("\n=== Creating a role with ABAC permissions ===")
	managerRole, err := service.CreateRole(ctx, CreateRoleRequest{
		Name:        "manager",
		Description: "Department manager with team access",
		Permissions: []Permission{
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
			{
				Resource: "project",
				Action:   "manage",
				Scope:    "group",
				Attributes: map[string]any{
					"department": "engineering",
				},
			},
		},
	})
	if err != nil {
		log.Printf("Error creating manager role: %v", err)
		return
	}
	fmt.Printf("Created role: %s (ID: %s)\n", managerRole.Name, managerRole.ID)

	// Example 4: Assign roles to users
	fmt.Println("\n=== Assigning roles to users ===")
	userID := uuid.New()
	adminID := uuid.New()

	// Assign user role to regular user
	err = service.AssignRoleToUser(ctx, userID, userRole.ID, adminID)
	if err != nil {
		log.Printf("Error assigning user role: %v", err)
		return
	}
	fmt.Printf("Assigned role '%s' to user %s\n", userRole.Name, userID)

	// Assign manager role to user as well (users can have multiple roles)
	err = service.AssignRoleToUser(ctx, userID, managerRole.ID, adminID)
	if err != nil {
		log.Printf("Error assigning manager role: %v", err)
		return
	}
	fmt.Printf("Assigned role '%s' to user %s\n", managerRole.Name, userID)

	// Example 5: Validate permissions
	fmt.Println("\n=== Validating permissions ===")

	// Check if user can read their own profile
	canReadOwn, err := service.ValidatePermission(ctx, userID, PermUserReadOwn)
	if err != nil {
		log.Printf("Error validating permission: %v", err)
		return
	}
	fmt.Printf("User can read own profile: %v\n", canReadOwn)

	// Check if user can manage all users (should be false)
	canManageAll, err := service.ValidatePermission(ctx, userID, PermUserManageAll)
	if err != nil {
		log.Printf("Error validating permission: %v", err)
		return
	}
	fmt.Printf("User can manage all users: %v\n", canManageAll)

	// Example 6: Attribute-based access control
	fmt.Println("\n=== Testing attribute-based access control ===")

	// Test access to engineering department documents
	accessReq := AccessRequest{
		UserID:   userID,
		Resource: "document",
		Action:   "read",
		Scope:    "group",
		Attributes: map[string]any{
			"department": "engineering",
			"clearance":  "internal",
		},
	}

	accessResp, err := service.ValidateAccess(ctx, accessReq)
	if err != nil {
		log.Printf("Error validating access: %v", err)
		return
	}
	fmt.Printf("Access to engineering documents allowed: %v\n", accessResp.Allowed)
	if !accessResp.Allowed {
		fmt.Printf("Reason: %s\n", accessResp.Reason)
	}

	// Test access to marketing department documents (should be denied)
	accessReq.Attributes["department"] = "marketing"
	accessResp, err = service.ValidateAccess(ctx, accessReq)
	if err != nil {
		log.Printf("Error validating access: %v", err)
		return
	}
	fmt.Printf("Access to marketing documents allowed: %v\n", accessResp.Allowed)
	if !accessResp.Allowed {
		fmt.Printf("Reason: %s\n", accessResp.Reason)
	}

	// Example 7: List all user permissions
	fmt.Println("\n=== Listing user permissions ===")
	permissions, err := service.GetUserPermissions(ctx, userID)
	if err != nil {
		log.Printf("Error getting user permissions: %v", err)
		return
	}
	fmt.Printf("User has %d permissions:\n", len(permissions))
	for _, perm := range permissions {
		fmt.Printf("  - %s\n", perm.String())
	}

	// Example 8: Update a role
	fmt.Println("\n=== Updating a role ===")
	newDescription := "Updated user role with additional permissions"
	updatedPermissions := []Permission{
		PermUserReadOwn,
		PermUserUpdateOwn,
		{Resource: "profile", Action: "read", Scope: "own"},
	}

	updatedRole, err := service.UpdateRole(ctx, userRole.ID, UpdateRoleRequest{
		Description: &newDescription,
		Permissions: updatedPermissions,
	})
	if err != nil {
		log.Printf("Error updating role: %v", err)
		return
	}
	fmt.Printf("Updated role '%s' with %d permissions\n", updatedRole.Name, len(updatedRole.Permissions))

	// Example 9: List roles with pagination
	fmt.Println("\n=== Listing roles ===")
	rolesList, err := service.ListRoles(ctx, ListRolesRequest{
		Limit:  10,
		Offset: 0,
	})
	if err != nil {
		log.Printf("Error listing roles: %v", err)
		return
	}
	fmt.Printf("Found %d roles (total: %d):\n", len(rolesList.Roles), rolesList.Total)
	for _, role := range rolesList.Roles {
		fmt.Printf("  - %s: %s (%d permissions)\n", role.Name, role.Description, len(role.Permissions))
	}

	fmt.Println("\n=== Role service example completed ===")
}

// ExampleRoleDefinitions shows common role patterns
func ExampleRoleDefinitions() {
	fmt.Println("=== Common Role Patterns ===")

	// Super Admin - Full system access
	superAdmin := CreateRoleRequest{
		Name:        "super-admin",
		Description: "Super administrator with unrestricted access",
		Permissions: []Permission{
			{Resource: "*", Action: "*"},
		},
	}
	fmt.Printf("Super Admin: %d permissions\n", len(superAdmin.Permissions))

	// System Admin - System management without user data access
	systemAdmin := CreateRoleRequest{
		Name:        "system-admin",
		Description: "System administrator for infrastructure management",
		Permissions: []Permission{
			PermSystemRead,
			PermSystemManage,
			PermAuditRead,
			{Resource: "monitoring", Action: "read"},
			{Resource: "monitoring", Action: "manage"},
			{Resource: "backup", Action: "manage"},
		},
	}
	fmt.Printf("System Admin: %d permissions\n", len(systemAdmin.Permissions))

	// User Admin - User and role management
	userAdmin := CreateRoleRequest{
		Name:        "user-admin",
		Description: "User administrator for account management",
		Permissions: []Permission{
			PermUserReadAll,
			PermUserManageAll,
			PermRoleRead,
			PermRoleManage,
			{Resource: "session", Action: "read", Scope: "all"},
			{Resource: "session", Action: "manage", Scope: "all"},
		},
	}
	fmt.Printf("User Admin: %d permissions\n", len(userAdmin.Permissions))

	// Department Manager - Team-specific access
	deptManager := CreateRoleRequest{
		Name:        "dept-manager",
		Description: "Department manager with team oversight",
		Permissions: []Permission{
			{
				Resource: "user",
				Action:   "read",
				Scope:    "group",
				Attributes: map[string]any{
					"department": "${user.department}",
				},
			},
			{
				Resource: "user",
				Action:   "update",
				Scope:    "group",
				Attributes: map[string]any{
					"department": "${user.department}",
					"level":      "<=manager",
				},
			},
			{
				Resource: "project",
				Action:   "manage",
				Scope:    "group",
				Attributes: map[string]any{
					"department": "${user.department}",
				},
			},
		},
	}
	fmt.Printf("Department Manager: %d permissions\n", len(deptManager.Permissions))

	// Regular User - Basic self-service
	regularUser := CreateRoleRequest{
		Name:        "user",
		Description: "Regular user with self-service capabilities",
		Permissions: []Permission{
			PermUserReadOwn,
			PermUserUpdateOwn,
			{Resource: "profile", Action: "read", Scope: "own"},
			{Resource: "profile", Action: "update", Scope: "own"},
			{Resource: "session", Action: "read", Scope: "own"},
			{Resource: "session", Action: "manage", Scope: "own"},
		},
	}
	fmt.Printf("Regular User: %d permissions\n", len(regularUser.Permissions))

	// Read-Only User - View access only
	readOnlyUser := CreateRoleRequest{
		Name:        "readonly",
		Description: "Read-only user for viewing purposes",
		Permissions: []Permission{
			PermUserReadOwn,
			{Resource: "profile", Action: "read", Scope: "own"},
			{Resource: "document", Action: "read", Scope: "public"},
			{Resource: "report", Action: "read", Scope: "public"},
		},
	}
	fmt.Printf("Read-Only User: %d permissions\n", len(readOnlyUser.Permissions))

	// API Service - Service-to-service access
	apiService := CreateRoleRequest{
		Name:        "api-service",
		Description: "API service account for automated operations",
		Permissions: []Permission{
			{Resource: "user", Action: "read", Scope: "all"},
			{Resource: "user", Action: "create"},
			{Resource: "session", Action: "create"},
			{Resource: "session", Action: "validate"},
			{Resource: "audit", Action: "create"},
		},
	}
	fmt.Printf("API Service: %d permissions\n", len(apiService.Permissions))
}
