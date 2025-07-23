package interfaces

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Role represents a role with permissions
type Role struct {
	ID          uuid.UUID    `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	Permissions []Permission `json:"permissions"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

// Permission represents a specific permission
type Permission struct {
	Resource   string         `json:"resource"`
	Action     string         `json:"action"`
	Scope      string         `json:"scope,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// String returns a string representation of the permission
func (p Permission) String() string {
	if p.Scope != "" {
		return p.Resource + ":" + p.Action + ":" + p.Scope
	}
	return p.Resource + ":" + p.Action
}

// UserInfo represents basic user information for role assignments
type UserInfo struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Username  string    `json:"username,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateRoleRequest represents a request to create a new role
type CreateRoleRequest struct {
	Name        string       `json:"name" validate:"required,min=1,max=100"`
	Description string       `json:"description,omitempty" validate:"max=500"`
	Permissions []Permission `json:"permissions,omitempty"`
}

// UpdateRoleRequest represents a request to update an existing role
type UpdateRoleRequest struct {
	Name        *string      `json:"name,omitempty" validate:"omitempty,min=1,max=100"`
	Description *string      `json:"description,omitempty" validate:"omitempty,max=500"`
	Permissions []Permission `json:"permissions,omitempty"`
}

// ListRolesRequest represents a request to list roles
type ListRolesRequest struct {
	Limit  int `json:"limit" validate:"min=1,max=100"`
	Offset int `json:"offset" validate:"min=0"`
}

// ListRolesResponse represents a response containing a list of roles
type ListRolesResponse struct {
	Roles   []*Role `json:"roles"`
	Total   int64   `json:"total"`
	Limit   int     `json:"limit"`
	Offset  int     `json:"offset"`
	HasMore bool    `json:"has_more"`
}

// AccessRequest represents a request for access validation
type AccessRequest struct {
	UserID     uuid.UUID      `json:"user_id"`
	Resource   string         `json:"resource"`
	Action     string         `json:"action"`
	Scope      string         `json:"scope,omitempty"`
	Context    map[string]any `json:"context,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// AccessResponse represents the result of access validation
type AccessResponse struct {
	Allowed            bool           `json:"allowed"`
	Reason             string         `json:"reason,omitempty"`
	MatchedPermissions []Permission   `json:"matched_permissions,omitempty"`
	Context            map[string]any `json:"context,omitempty"`
}

// PermissionSet represents a set of permissions for efficient lookups
type PermissionSet map[string]bool

// NewPermissionSet creates a new permission set from a slice of permissions
func NewPermissionSet(permissions []Permission) PermissionSet {
	set := make(PermissionSet)
	for _, perm := range permissions {
		set[perm.String()] = true
		// Also add wildcard patterns
		set[perm.Resource+":*"] = true
		set["*:"+perm.Action] = true
		set["*:*"] = true
	}
	return set
}

// Contains checks if the permission set contains a specific permission
func (ps PermissionSet) Contains(permission Permission) bool {
	// Check exact match
	if ps[permission.String()] {
		return true
	}

	// Check wildcard patterns
	if ps[permission.Resource+":*"] {
		return true
	}

	if ps["*:"+permission.Action] {
		return true
	}

	if ps["*:*"] {
		return true
	}

	return false
}

// MarshalPermissions converts permissions slice to JSON for database storage
func MarshalPermissions(permissions []Permission) ([]byte, error) {
	return json.Marshal(permissions)
}

// UnmarshalPermissions converts JSON to permissions slice from database
func UnmarshalPermissions(data []byte) ([]Permission, error) {
	var permissions []Permission
	if len(data) == 0 {
		return permissions, nil
	}
	err := json.Unmarshal(data, &permissions)
	return permissions, err
}

// Role template functions for common roles

// NewGuestRole creates a basic guest role with minimal permissions
func NewGuestRole() *Role {
	return &Role{
		Name:        "guest",
		Description: "Guest user with minimal access",
		Permissions: []Permission{
			PermUserReadOwn,
		},
	}
}

// NewUserRole creates a standard user role
func NewUserRole() *Role {
	return &Role{
		Name:        "user",
		Description: "Standard user with basic permissions",
		Permissions: []Permission{
			PermUserReadOwn,
			PermUserUpdateOwn,
			PermSessionRead,
		},
	}
}

// NewModeratorRole creates a moderator role with extended permissions
func NewModeratorRole() *Role {
	return &Role{
		Name:        "moderator",
		Description: "Moderator with user management permissions",
		Permissions: []Permission{
			PermUserReadOwn,
			PermUserUpdateOwn,
			PermUserReadAll,
			PermSessionRead,
			PermRoleRead,
		},
	}
}

// NewAdminRole creates an admin role with comprehensive permissions
func NewAdminRole() *Role {
	return &Role{
		Name:        "admin",
		Description: "Administrator with full system access",
		Permissions: []Permission{
			PermUserManageAll,
			PermRoleManage,
			PermSessionManage,
			PermSystemRead,
			PermAuditRead,
		},
	}
}

// NewSuperUserRole creates a superuser role with all permissions
func NewSuperUserRole() *Role {
	return &Role{
		Name:        "superuser",
		Description: "Super user with unrestricted access",
		Permissions: []Permission{
			{Resource: "*", Action: "*", Scope: ScopeAll},
		},
	}
}

// HasPermission checks if a role has a specific permission
func (r *Role) HasPermission(permission Permission) bool {
	permSet := NewPermissionSet(r.Permissions)
	return permSet.Contains(permission)
}

// AddPermission adds a permission to the role if it doesn't already exist
func (r *Role) AddPermission(permission Permission) {
	if !r.HasPermission(permission) {
		r.Permissions = append(r.Permissions, permission)
	}
}

// RemovePermission removes a permission from the role
func (r *Role) RemovePermission(permission Permission) {
	var filtered []Permission
	for _, perm := range r.Permissions {
		if perm.String() != permission.String() {
			filtered = append(filtered, perm)
		}
	}
	r.Permissions = filtered
}

// Common permission constants
const (
	// Resources
	ResourceUser    = "user"
	ResourceRole    = "role"
	ResourceSession = "session"
	ResourceAudit   = "audit"
	ResourceSystem  = "system"

	// Actions
	ActionCreate = "create"
	ActionRead   = "read"
	ActionUpdate = "update"
	ActionDelete = "delete"
	ActionList   = "list"
	ActionManage = "manage"

	// Scopes
	ScopeOwn   = "own"
	ScopeAll   = "all"
	ScopeGroup = "group"
)

// Common permissions
var (
	// User permissions
	PermUserCreateOwn = Permission{Resource: ResourceUser, Action: ActionCreate, Scope: ScopeOwn}
	PermUserReadOwn   = Permission{Resource: ResourceUser, Action: ActionRead, Scope: ScopeOwn}
	PermUserUpdateOwn = Permission{Resource: ResourceUser, Action: ActionUpdate, Scope: ScopeOwn}
	PermUserDeleteOwn = Permission{Resource: ResourceUser, Action: ActionDelete, Scope: ScopeOwn}
	PermUserReadAll   = Permission{Resource: ResourceUser, Action: ActionRead, Scope: ScopeAll}
	PermUserManageAll = Permission{Resource: ResourceUser, Action: ActionManage, Scope: ScopeAll}

	// Role permissions
	PermRoleCreate = Permission{Resource: ResourceRole, Action: ActionCreate}
	PermRoleRead   = Permission{Resource: ResourceRole, Action: ActionRead}
	PermRoleUpdate = Permission{Resource: ResourceRole, Action: ActionUpdate}
	PermRoleDelete = Permission{Resource: ResourceRole, Action: ActionDelete}
	PermRoleManage = Permission{Resource: ResourceRole, Action: ActionManage}

	// System permissions
	PermSystemRead   = Permission{Resource: ResourceSystem, Action: ActionRead}
	PermSystemManage = Permission{Resource: ResourceSystem, Action: ActionManage}

	// Audit permissions
	PermAuditRead = Permission{Resource: ResourceAudit, Action: ActionRead}

	// Session permissions
	PermSessionRead   = Permission{Resource: ResourceSession, Action: ActionRead, Scope: ScopeOwn}
	PermSessionManage = Permission{Resource: ResourceSession, Action: ActionManage, Scope: ScopeAll}
)
