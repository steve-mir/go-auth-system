package role1

import (
	"context"

	"github.com/google/uuid"
)

// Service defines the interface for role management operations
type Service interface {
	// Role management
	CreateRole(ctx context.Context, req CreateRoleRequest) (*Role, error)
	GetRole(ctx context.Context, roleID uuid.UUID) (*Role, error)
	GetRoleByName(ctx context.Context, name string) (*Role, error)
	UpdateRole(ctx context.Context, roleID uuid.UUID, req UpdateRoleRequest) (*Role, error)
	DeleteRole(ctx context.Context, roleID uuid.UUID) error
	ListRoles(ctx context.Context, req ListRolesRequest) (*ListRolesResponse, error)

	// User-role assignment
	AssignRoleToUser(ctx context.Context, userID, roleID uuid.UUID, assignedBy uuid.UUID) error
	RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error
	GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*Role, error)
	GetRoleUsers(ctx context.Context, roleID uuid.UUID) ([]*UserInfo, error)

	// Permission validation
	ValidatePermission(ctx context.Context, userID uuid.UUID, permission Permission) (bool, error)
	ValidatePermissions(ctx context.Context, userID uuid.UUID, permissions []Permission) (map[string]bool, error)
	GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]Permission, error)

	// Attribute-based access control
	ValidateAccess(ctx context.Context, req AccessRequest) (*AccessResponse, error)

	// Advanced permission management
	GetEffectivePermissions(ctx context.Context, userID uuid.UUID) ([]Permission, error)
	CheckResourceAccess(ctx context.Context, userID uuid.UUID, resource string, actions []string) (map[string]bool, error)
	ValidateRoleHierarchy(ctx context.Context, userID uuid.UUID, requiredRole string) (bool, error)
}

// Repository defines the interface for role data access
type Repository interface {
	// Role CRUD operations
	CreateRole(ctx context.Context, role *Role) error
	GetRoleByID(ctx context.Context, roleID uuid.UUID) (*Role, error)
	GetRoleByName(ctx context.Context, name string) (*Role, error)
	UpdateRole(ctx context.Context, role *Role) error
	DeleteRole(ctx context.Context, roleID uuid.UUID) error
	ListRoles(ctx context.Context, limit, offset int) ([]*Role, error)
	CountRoles(ctx context.Context) (int64, error)

	// User-role relationships
	AssignRoleToUser(ctx context.Context, userID, roleID, assignedBy uuid.UUID) error
	RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error
	GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*Role, error)
	GetRoleUsers(ctx context.Context, roleID uuid.UUID) ([]*UserInfo, error)
}
