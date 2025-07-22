package role

import (
	"fmt"

	"github.com/steve-mir/go-auth-system/internal/errors"
)

// Error codes for role service
const (
	ErrCodeRoleNotFound           = "ROLE_NOT_FOUND"
	ErrCodeRoleAlreadyExists      = "ROLE_ALREADY_EXISTS"
	ErrCodeRoleInUse              = "ROLE_IN_USE"
	ErrCodeInvalidPermission      = "INVALID_PERMISSION"
	ErrCodeUserRoleNotFound       = "USER_ROLE_NOT_FOUND"
	ErrCodeUserRoleExists         = "USER_ROLE_EXISTS"
	ErrCodeAccessDenied           = "ACCESS_DENIED"
	ErrCodeInvalidRoleData        = "INVALID_ROLE_DATA"
	ErrCodePermissionDenied       = "PERMISSION_DENIED"
	ErrCodeInsufficientPrivilege  = "INSUFFICIENT_PRIVILEGE"
	ErrCodeRoleHierarchyViolation = "ROLE_HIERARCHY_VIOLATION"
)

// Role service specific errors
var (
	ErrRoleNotFound = &errors.AppError{
		Type:    errors.ErrorTypeNotFound,
		Code:    ErrCodeRoleNotFound,
		Message: "role not found",
	}

	ErrRoleAlreadyExists = &errors.AppError{
		Type:    errors.ErrorTypeConflict,
		Code:    ErrCodeRoleAlreadyExists,
		Message: "role already exists",
	}

	ErrRoleInUse = &errors.AppError{
		Type:    errors.ErrorTypeConflict,
		Code:    ErrCodeRoleInUse,
		Message: "role is currently in use and cannot be deleted",
	}

	ErrInvalidPermission = &errors.AppError{
		Type:    errors.ErrorTypeValidation,
		Code:    ErrCodeInvalidPermission,
		Message: "invalid permission format",
	}

	ErrUserRoleNotFound = &errors.AppError{
		Type:    errors.ErrorTypeNotFound,
		Code:    ErrCodeUserRoleNotFound,
		Message: "user role assignment not found",
	}

	ErrUserRoleExists = &errors.AppError{
		Type:    errors.ErrorTypeConflict,
		Code:    ErrCodeUserRoleExists,
		Message: "user role assignment already exists",
	}

	ErrAccessDenied = &errors.AppError{
		Type:    errors.ErrorTypeAuthorization,
		Code:    ErrCodeAccessDenied,
		Message: "access denied",
	}

	ErrInvalidRoleData = &errors.AppError{
		Type:    errors.ErrorTypeValidation,
		Code:    ErrCodeInvalidRoleData,
		Message: "invalid role data",
	}

	ErrPermissionDenied = &errors.AppError{
		Type:    errors.ErrorTypeAuthorization,
		Code:    ErrCodePermissionDenied,
		Message: "permission denied",
	}
)

// NewRoleNotFoundError creates a new role not found error with context
func NewRoleNotFoundError(identifier string) *errors.AppError {
	return &errors.AppError{
		Type:    errors.ErrorTypeNotFound,
		Code:    ErrCodeRoleNotFound,
		Message: fmt.Sprintf("role not found: %s", identifier),
		Details: map[string]any{
			"identifier": identifier,
		},
	}
}

// NewRoleAlreadyExistsError creates a new role already exists error with context
func NewRoleAlreadyExistsError(name string) *errors.AppError {
	return &errors.AppError{
		Type:    errors.ErrorTypeConflict,
		Code:    ErrCodeRoleAlreadyExists,
		Message: fmt.Sprintf("role already exists: %s", name),
		Details: map[string]any{
			"name": name,
		},
	}
}

// NewInvalidPermissionError creates a new invalid permission error with context
func NewInvalidPermissionError(permission string, reason string) *errors.AppError {
	return &errors.AppError{
		Type:    errors.ErrorTypeValidation,
		Code:    ErrCodeInvalidPermission,
		Message: fmt.Sprintf("invalid permission '%s': %s", permission, reason),
		Details: map[string]any{
			"permission": permission,
			"reason":     reason,
		},
	}
}

// NewAccessDeniedError creates a new access denied error with context
func NewAccessDeniedError(resource, action string) *errors.AppError {
	return &errors.AppError{
		Type:    errors.ErrorTypeAuthorization,
		Code:    ErrCodeAccessDenied,
		Message: fmt.Sprintf("access denied for %s:%s", resource, action),
		Details: map[string]any{
			"resource": resource,
			"action":   action,
		},
	}
}

// NewPermissionDeniedError creates a new permission denied error with context
func NewPermissionDeniedError(userID, permission string) *errors.AppError {
	return &errors.AppError{
		Type:    errors.ErrorTypeAuthorization,
		Code:    ErrCodePermissionDenied,
		Message: fmt.Sprintf("user %s does not have permission: %s", userID, permission),
		Details: map[string]any{
			"user_id":    userID,
			"permission": permission,
		},
	}
}

// NewInsufficientPrivilegeError creates a new insufficient privilege error
func NewInsufficientPrivilegeError(userID, requiredRole string) *errors.AppError {
	return &errors.AppError{
		Type:    errors.ErrorTypeAuthorization,
		Code:    ErrCodeInsufficientPrivilege,
		Message: fmt.Sprintf("user %s does not have required privilege level: %s", userID, requiredRole),
		Details: map[string]any{
			"user_id":       userID,
			"required_role": requiredRole,
		},
	}
}

// NewRoleHierarchyViolationError creates a new role hierarchy violation error
func NewRoleHierarchyViolationError(action, reason string) *errors.AppError {
	return &errors.AppError{
		Type:    errors.ErrorTypeAuthorization,
		Code:    ErrCodeRoleHierarchyViolation,
		Message: fmt.Sprintf("role hierarchy violation: %s - %s", action, reason),
		Details: map[string]any{
			"action": action,
			"reason": reason,
		},
	}
}
