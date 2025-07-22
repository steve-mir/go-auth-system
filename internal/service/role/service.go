package role

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/steve-mir/go-auth-system/internal/errors"
)

// service implements the Service interface
type service struct {
	repo      Repository
	validator *validator.Validate
}

// NewService creates a new role service
func NewService(repo Repository) Service {
	return &service{
		repo:      repo,
		validator: validator.New(),
	}
}

// CreateRole creates a new role
func (s *service) CreateRole(ctx context.Context, req CreateRoleRequest) (*Role, error) {
	// Validate request
	if err := s.validator.Struct(req); err != nil {
		return nil, &errors.AppError{
			Type:    errors.ErrorTypeValidation,
			Code:    ErrCodeInvalidRoleData,
			Message: "invalid role data",
			Details: err,
		}
	}

	// Validate permissions
	if err := s.validatePermissions(req.Permissions); err != nil {
		return nil, err
	}

	// Check if role already exists
	existingRole, err := s.repo.GetRoleByName(ctx, req.Name)
	if err == nil && existingRole != nil {
		return nil, NewRoleAlreadyExistsError(req.Name)
	}

	// Create role
	role := &Role{
		Name:        req.Name,
		Description: req.Description,
		Permissions: req.Permissions,
	}

	if err := s.repo.CreateRole(ctx, role); err != nil {
		return nil, err
	}

	return role, nil
}

// GetRole retrieves a role by ID
func (s *service) GetRole(ctx context.Context, roleID uuid.UUID) (*Role, error) {
	return s.repo.GetRoleByID(ctx, roleID)
}

// GetRoleByName retrieves a role by name
func (s *service) GetRoleByName(ctx context.Context, name string) (*Role, error) {
	return s.repo.GetRoleByName(ctx, name)
}

// UpdateRole updates an existing role
func (s *service) UpdateRole(ctx context.Context, roleID uuid.UUID, req UpdateRoleRequest) (*Role, error) {
	// Validate request
	if err := s.validator.Struct(req); err != nil {
		return nil, &errors.AppError{
			Type:    errors.ErrorTypeValidation,
			Code:    ErrCodeInvalidRoleData,
			Message: "invalid role data",
			Details: err,
		}
	}

	// Get existing role
	role, err := s.repo.GetRoleByID(ctx, roleID)
	if err != nil {
		return nil, err
	}

	// Update fields if provided
	if req.Name != nil {
		// Check if new name conflicts with existing role
		if *req.Name != role.Name {
			existingRole, err := s.repo.GetRoleByName(ctx, *req.Name)
			if err == nil && existingRole != nil {
				return nil, NewRoleAlreadyExistsError(*req.Name)
			}
		}
		role.Name = *req.Name
	}

	if req.Description != nil {
		role.Description = *req.Description
	}

	if req.Permissions != nil {
		// Validate permissions
		if err := s.validatePermissions(req.Permissions); err != nil {
			return nil, err
		}
		role.Permissions = req.Permissions
	}

	// Update role
	if err := s.repo.UpdateRole(ctx, role); err != nil {
		return nil, err
	}

	return role, nil
}

// DeleteRole deletes a role
func (s *service) DeleteRole(ctx context.Context, roleID uuid.UUID) error {
	// Check if role exists
	_, err := s.repo.GetRoleByID(ctx, roleID)
	if err != nil {
		return err
	}

	// Check if role is in use
	users, err := s.repo.GetRoleUsers(ctx, roleID)
	if err != nil {
		return err
	}

	if len(users) > 0 {
		return &errors.AppError{
			Type:    errors.ErrorTypeConflict,
			Code:    ErrCodeRoleInUse,
			Message: fmt.Sprintf("role is assigned to %d users and cannot be deleted", len(users)),
			Details: map[string]any{
				"role_id":    roleID,
				"user_count": len(users),
			},
		}
	}

	return s.repo.DeleteRole(ctx, roleID)
}

// ListRoles retrieves a paginated list of roles
func (s *service) ListRoles(ctx context.Context, req ListRolesRequest) (*ListRolesResponse, error) {
	// Validate request
	if err := s.validator.Struct(req); err != nil {
		return nil, &errors.AppError{
			Type:    errors.ErrorTypeValidation,
			Code:    ErrCodeInvalidRoleData,
			Message: "invalid list request",
			Details: err,
		}
	}

	// Set defaults
	if req.Limit <= 0 {
		req.Limit = 20
	}
	if req.Limit > 100 {
		req.Limit = 100
	}

	// Get roles and total count
	roles, err := s.repo.ListRoles(ctx, req.Limit, req.Offset)
	if err != nil {
		return nil, err
	}

	total, err := s.repo.CountRoles(ctx)
	if err != nil {
		return nil, err
	}

	return &ListRolesResponse{
		Roles:   roles,
		Total:   total,
		Limit:   req.Limit,
		Offset:  req.Offset,
		HasMore: int64(req.Offset+req.Limit) < total,
	}, nil
}

// AssignRoleToUser assigns a role to a user
func (s *service) AssignRoleToUser(ctx context.Context, userID, roleID uuid.UUID, assignedBy uuid.UUID) error {
	// Check if role exists
	_, err := s.repo.GetRoleByID(ctx, roleID)
	if err != nil {
		return err
	}

	// Assign role
	return s.repo.AssignRoleToUser(ctx, userID, roleID, assignedBy)
}

// RemoveRoleFromUser removes a role from a user
func (s *service) RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	return s.repo.RemoveRoleFromUser(ctx, userID, roleID)
}

// GetUserRoles retrieves all roles assigned to a user
func (s *service) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*Role, error) {
	return s.repo.GetUserRoles(ctx, userID)
}

// GetRoleUsers retrieves all users assigned to a role
func (s *service) GetRoleUsers(ctx context.Context, roleID uuid.UUID) ([]*UserInfo, error) {
	return s.repo.GetRoleUsers(ctx, roleID)
}

// ValidatePermission checks if a user has a specific permission
func (s *service) ValidatePermission(ctx context.Context, userID uuid.UUID, permission Permission) (bool, error) {
	userRoles, err := s.repo.GetUserRoles(ctx, userID)
	if err != nil {
		return false, err
	}

	// Collect all permissions from user roles
	var allPermissions []Permission
	for _, role := range userRoles {
		allPermissions = append(allPermissions, role.Permissions...)
	}

	// Create permission set for efficient lookup
	permissionSet := NewPermissionSet(allPermissions)

	return permissionSet.Contains(permission), nil
}

// ValidatePermissions checks if a user has multiple permissions
func (s *service) ValidatePermissions(ctx context.Context, userID uuid.UUID, permissions []Permission) (map[string]bool, error) {
	userRoles, err := s.repo.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Collect all permissions from user roles
	var allPermissions []Permission
	for _, role := range userRoles {
		allPermissions = append(allPermissions, role.Permissions...)
	}

	// Create permission set for efficient lookup
	permissionSet := NewPermissionSet(allPermissions)

	// Check each permission
	result := make(map[string]bool)
	for _, permission := range permissions {
		result[permission.String()] = permissionSet.Contains(permission)
	}

	return result, nil
}

// GetUserPermissions retrieves all permissions for a user
func (s *service) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]Permission, error) {
	userRoles, err := s.repo.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Collect all permissions from user roles
	var allPermissions []Permission
	permissionMap := make(map[string]Permission) // Use map to deduplicate

	for _, role := range userRoles {
		for _, permission := range role.Permissions {
			permissionMap[permission.String()] = permission
		}
	}

	// Convert map back to slice
	for _, permission := range permissionMap {
		allPermissions = append(allPermissions, permission)
	}

	return allPermissions, nil
}

// ValidateAccess performs attribute-based access control validation
func (s *service) ValidateAccess(ctx context.Context, req AccessRequest) (*AccessResponse, error) {
	// Get user permissions
	userPermissions, err := s.GetUserPermissions(ctx, req.UserID)
	if err != nil {
		return &AccessResponse{
			Allowed: false,
			Reason:  "failed to retrieve user permissions",
		}, err
	}

	// Create the requested permission
	requestedPermission := Permission{
		Resource:   req.Resource,
		Action:     req.Action,
		Scope:      req.Scope,
		Attributes: req.Attributes,
	}

	// Check basic permission
	permissionSet := NewPermissionSet(userPermissions)
	if !permissionSet.Contains(requestedPermission) {
		return &AccessResponse{
			Allowed: false,
			Reason:  fmt.Sprintf("user does not have permission: %s", requestedPermission.String()),
		}, nil
	}

	// Find matching permissions for detailed response
	var matchedPermissions []Permission
	for _, perm := range userPermissions {
		if s.permissionMatches(perm, requestedPermission, req.Context) {
			matchedPermissions = append(matchedPermissions, perm)
		}
	}

	// Perform attribute-based validation
	allowed := s.validateAttributes(matchedPermissions, req)

	response := &AccessResponse{
		Allowed:            allowed,
		MatchedPermissions: matchedPermissions,
		Context:            req.Context,
	}

	if !allowed {
		response.Reason = "access denied by attribute-based access control"
	}

	return response, nil
}

// validatePermissions validates a slice of permissions
func (s *service) validatePermissions(permissions []Permission) error {
	for _, perm := range permissions {
		if err := s.validatePermission(perm); err != nil {
			return err
		}
	}
	return nil
}

// validatePermission validates a single permission
func (s *service) validatePermission(perm Permission) error {
	if perm.Resource == "" {
		return NewInvalidPermissionError(perm.String(), "resource cannot be empty")
	}

	if perm.Action == "" {
		return NewInvalidPermissionError(perm.String(), "action cannot be empty")
	}

	// Validate resource format
	if strings.Contains(perm.Resource, ":") {
		return NewInvalidPermissionError(perm.String(), "resource cannot contain colon character")
	}

	// Validate action format
	if strings.Contains(perm.Action, ":") {
		return NewInvalidPermissionError(perm.String(), "action cannot contain colon character")
	}

	return nil
}

// permissionMatches checks if a permission matches the requested permission with context
func (s *service) permissionMatches(userPerm, requestedPerm Permission, context map[string]any) bool {
	// Basic permission matching
	permSet := NewPermissionSet([]Permission{userPerm})
	if !permSet.Contains(requestedPerm) {
		return false
	}

	// Additional context-based matching
	if len(context) > 0 && len(userPerm.Attributes) > 0 {
		// Check if context values match permission attributes
		for key, expectedValue := range userPerm.Attributes {
			if contextValue, exists := context[key]; exists {
				if !s.valuesMatch(expectedValue, contextValue) {
					return false
				}
			}
		}
	}

	return true
}

// validateAttributes performs attribute-based access control validation
func (s *service) validateAttributes(permissions []Permission, req AccessRequest) bool {
	if len(permissions) == 0 {
		return false
	}

	// For each matching permission, check if attributes allow access
	for _, perm := range permissions {
		if s.attributesMatch(perm.Attributes, req.Attributes, req.Context) {
			return true
		}
	}

	return false
}

// attributesMatch checks if permission attributes match the request attributes
func (s *service) attributesMatch(permAttrs, reqAttrs, context map[string]any) bool {
	// If permission has no attribute restrictions, allow access
	if len(permAttrs) == 0 {
		return true
	}

	// Check each permission attribute against request attributes and context
	for key, expectedValue := range permAttrs {
		// Check in request attributes first
		if reqValue, exists := reqAttrs[key]; exists {
			if !s.valuesMatch(expectedValue, reqValue) {
				return false
			}
			continue
		}

		// Check in context
		if contextValue, exists := context[key]; exists {
			if !s.valuesMatch(expectedValue, contextValue) {
				return false
			}
			continue
		}

		// Required attribute not found
		return false
	}

	return true
}

// valuesMatch compares two values for attribute matching
func (s *service) valuesMatch(expected, actual any) bool {
	// Handle different types of matching
	switch expectedVal := expected.(type) {
	case string:
		if actualStr, ok := actual.(string); ok {
			// Support wildcard matching
			if expectedVal == "*" {
				return true
			}
			// Support prefix matching with *
			if strings.HasSuffix(expectedVal, "*") {
				prefix := strings.TrimSuffix(expectedVal, "*")
				return strings.HasPrefix(actualStr, prefix)
			}
			return expectedVal == actualStr
		}
	case []any:
		// Support array contains matching
		for _, item := range expectedVal {
			if s.valuesMatch(item, actual) {
				return true
			}
		}
		return false
	default:
		// Simple equality check for other types
		return expected == actual
	}
	return false
}

// GetEffectivePermissions retrieves all effective permissions for a user with inheritance
func (s *service) GetEffectivePermissions(ctx context.Context, userID uuid.UUID) ([]Permission, error) {
	userRoles, err := s.repo.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Use a map to deduplicate permissions and handle inheritance
	effectivePerms := make(map[string]Permission)

	for _, role := range userRoles {
		for _, permission := range role.Permissions {
			key := permission.String()

			// If we already have this permission, merge attributes
			if existing, exists := effectivePerms[key]; exists {
				merged := s.mergePermissionAttributes(existing, permission)
				effectivePerms[key] = merged
			} else {
				effectivePerms[key] = permission
			}
		}
	}

	// Convert map back to slice
	var result []Permission
	for _, perm := range effectivePerms {
		result = append(result, perm)
	}

	return result, nil
}

// CheckResourceAccess checks access to a specific resource with multiple actions
func (s *service) CheckResourceAccess(ctx context.Context, userID uuid.UUID, resource string, actions []string) (map[string]bool, error) {
	userPermissions, err := s.GetEffectivePermissions(ctx, userID)
	if err != nil {
		return nil, err
	}

	permissionSet := NewPermissionSet(userPermissions)
	result := make(map[string]bool)

	for _, action := range actions {
		permission := Permission{
			Resource: resource,
			Action:   action,
		}
		result[action] = permissionSet.Contains(permission)
	}

	return result, nil
}

// ValidateRoleHierarchy checks if a user has a specific role or higher in hierarchy
func (s *service) ValidateRoleHierarchy(ctx context.Context, userID uuid.UUID, requiredRole string) (bool, error) {
	userRoles, err := s.repo.GetUserRoles(ctx, userID)
	if err != nil {
		return false, err
	}

	// Define role hierarchy (higher number = higher privilege)
	roleHierarchy := map[string]int{
		"guest":     1,
		"user":      2,
		"moderator": 3,
		"admin":     4,
		"superuser": 5,
	}

	requiredLevel, exists := roleHierarchy[requiredRole]
	if !exists {
		// If role not in hierarchy, check for exact match
		for _, role := range userRoles {
			if role.Name == requiredRole {
				return true, nil
			}
		}
		return false, nil
	}

	// Check if user has required level or higher
	for _, role := range userRoles {
		if userLevel, exists := roleHierarchy[role.Name]; exists {
			if userLevel >= requiredLevel {
				return true, nil
			}
		}
	}

	return false, nil
}

// mergePermissionAttributes merges attributes from two permissions
func (s *service) mergePermissionAttributes(existing, new Permission) Permission {
	merged := existing

	// If new permission has broader scope, use it
	if new.Scope == ScopeAll && existing.Scope != ScopeAll {
		merged.Scope = new.Scope
	}

	// Merge attributes - new attributes override existing ones
	if merged.Attributes == nil {
		merged.Attributes = make(map[string]any)
	}

	// Merge attributes - new attributes override existing ones
	for key, value := range new.Attributes {
		merged.Attributes[key] = value
	}

	return merged
}
