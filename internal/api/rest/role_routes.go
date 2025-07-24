package rest

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/steve-mir/go-auth-system/internal/interfaces"
	"github.com/steve-mir/go-auth-system/internal/monitoring"
	// "github.com/steve-mir/go-auth-system/internal/service/role"
)

// setupRoleRoutes configures role management routes
func (s *Server) setupRoleRoutes(group *gin.RouterGroup) {
	// All role routes require admin privileges
	group.Use(s.adminAuthorizationMiddleware())

	group.POST("", s.createRoleHandler)
	group.GET("", s.listRolesHandler)
	group.GET("/:role_id", s.getRoleHandler)
	group.PUT("/:role_id", s.updateRoleHandler)
	group.DELETE("/:role_id", s.deleteRoleHandler)

	// User-role assignment routes
	group.POST("/:role_id/users/:user_id", s.assignRoleToUserHandler)
	group.DELETE("/:role_id/users/:user_id", s.removeRoleFromUserHandler)
	group.GET("/:role_id/users", s.getRoleUsersHandler)

	// Permission validation routes
	group.POST("/validate-permission", s.validatePermissionHandler)
	group.POST("/validate-access", s.validateAccessHandler)
}

// createRoleHandler creates a new role
func (s *Server) createRoleHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	// Start monitoring trace
	var trace *monitoring.TraceContext
	if s.monitoring != nil {
		trace, ctx = s.monitoring.StartTrace(ctx, "create_role")
		c.Request = c.Request.WithContext(ctx)
	}

	var req interfaces.CreateRoleRequest
	if !s.bindAndValidate(c, &req) {
		if s.monitoring != nil {
			err := fmt.Errorf("invalid create role request")
			s.trackError(ctx, err, monitoring.ErrorCategoryValidation, "create_role", "role")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		return
	}

	// Sanitize input
	sanitizeStringField(&req.Name)
	sanitizeStringField(&req.Description)

	// Get admin user info for audit
	adminUserID, _, _, _ := s.getUserContext(c)

	createdRole, err := s.roleService.CreateRole(c.Request.Context(), req)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.ErrorCategoryService, "create_role", "role")
			s.trackSecurityEvent(ctx, "role_creation_failed", "medium", map[string]interface{}{
				"admin_user_id": adminUserID,
				"role_name":     req.Name,
				"error":         err.Error(),
				"ip":            c.ClientIP(),
			})
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.handleServiceError(c, err)
		return
	}

	// Track successful role creation
	if s.monitoring != nil {
		s.trackSecurityEvent(ctx, "role_created", "low", map[string]interface{}{
			"admin_user_id": adminUserID,
			"role_id":       createdRole.ID,
			"role_name":     createdRole.Name,
			"duration":      duration.Milliseconds(),
			"ip":            c.ClientIP(),
		})
		s.monitoring.RecordAuditEvent(ctx, "create_role", "role", adminUserID, map[string]interface{}{
			"role_id":   createdRole.ID,
			"role_name": createdRole.Name,
		})
		s.monitoring.FinishTrace(ctx, trace, nil)
	}

	s.successResponse(c, http.StatusCreated, createdRole)
}

// listRolesHandler lists all roles with pagination
func (s *Server) listRolesHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	// Start monitoring trace
	var trace *monitoring.TraceContext
	if s.monitoring != nil {
		trace, ctx = s.monitoring.StartTrace(ctx, "list_roles")
		c.Request = c.Request.WithContext(ctx)
	}

	page, limit, valid := s.GetPaginationParams(c)
	if !valid {
		if s.monitoring != nil {
			err := fmt.Errorf("invalid pagination parameters")
			s.trackError(ctx, err, monitoring.ErrorCategoryValidation, "list_roles", "role")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		return
	}

	req := interfaces.ListRolesRequest{
		Limit:  limit,
		Offset: (page - 1) * limit,
	}

	resp, err := s.roleService.ListRoles(c.Request.Context(), req)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.ErrorCategoryService, "list_roles", "role")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.handleServiceError(c, err)
		return
	}

	// Track successful role listing
	if s.monitoring != nil {
		adminUserID, _, _, _ := s.getUserContext(c)
		s.monitoring.RecordAuditEvent(ctx, "list_roles", "role", adminUserID, map[string]interface{}{
			"page":     page,
			"limit":    limit,
			"total":    resp.Total,
			"duration": duration.Milliseconds(),
		})
		s.monitoring.FinishTrace(ctx, trace, nil)
	}

	pagination := calculatePagination(page, limit, resp.Total)
	s.paginatedResponse(c, http.StatusOK, resp.Roles, pagination)
}

// getRoleHandler gets a role by ID
func (s *Server) getRoleHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	// Start monitoring trace
	var trace *monitoring.TraceContext
	if s.monitoring != nil {
		trace, ctx = s.monitoring.StartTrace(ctx, "get_role")
		c.Request = c.Request.WithContext(ctx)
	}

	roleIDStr, valid := s.parseUUIDParam(c, "role_id")
	if !valid {
		if s.monitoring != nil {
			err := fmt.Errorf("invalid role ID parameter")
			s.trackError(ctx, err, monitoring.ErrorCategoryValidation, "get_role", "role")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		return
	}

	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.ErrorCategoryValidation, "get_role", "role")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.badRequestResponse(c, "Invalid role ID format", nil)
		return
	}

	roleData, err := s.roleService.GetRole(c.Request.Context(), roleID)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.ErrorCategoryService, "get_role", "role")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.handleServiceError(c, err)
		return
	}

	// Track successful role retrieval
	if s.monitoring != nil {
		adminUserID, _, _, _ := s.getUserContext(c)
		s.monitoring.RecordAuditEvent(ctx, "get_role", "role", adminUserID, map[string]interface{}{
			"role_id":   roleID.String(),
			"role_name": roleData.Name,
			"duration":  duration.Milliseconds(),
		})
		s.monitoring.FinishTrace(ctx, trace, nil)
	}

	s.successResponse(c, http.StatusOK, roleData)
}

// updateRoleHandler updates a role
func (s *Server) updateRoleHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	// Start monitoring trace
	var trace *monitoring.TraceContext
	if s.monitoring != nil {
		trace, ctx = s.monitoring.StartTrace(ctx, "update_role")
		c.Request = c.Request.WithContext(ctx)
	}

	roleIDStr, valid := s.parseUUIDParam(c, "role_id")
	if !valid {
		if s.monitoring != nil {
			err := fmt.Errorf("invalid role ID parameter")
			s.trackError(ctx, err, monitoring.ErrorCategoryValidation, "update_role", "role")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		return
	}

	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.ErrorCategoryValidation, "update_role", "role")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.badRequestResponse(c, "Invalid role ID format", nil)
		return
	}

	var req interfaces.UpdateRoleRequest
	if !s.bindAndValidate(c, &req) {
		if s.monitoring != nil {
			err := fmt.Errorf("invalid update role request")
			s.trackError(ctx, err, monitoring.ErrorCategoryValidation, "update_role", "role")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		return
	}

	// Sanitize input
	if req.Name != nil {
		sanitizeStringField(req.Name)
	}
	if req.Description != nil {
		sanitizeStringField(req.Description)
	}

	// Get admin user info for audit
	adminUserID, _, _, _ := s.getUserContext(c)

	updatedRole, err := s.roleService.UpdateRole(c.Request.Context(), roleID, req)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.ErrorCategoryService, "update_role", "role")
			s.trackSecurityEvent(ctx, "role_update_failed", "medium", map[string]interface{}{
				"admin_user_id": adminUserID,
				"role_id":       roleID.String(),
				"error":         err.Error(),
				"ip":            c.ClientIP(),
			})
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.handleServiceError(c, err)
		return
	}

	// Track successful role update
	if s.monitoring != nil {
		s.trackSecurityEvent(ctx, "role_updated", "low", map[string]interface{}{
			"admin_user_id": adminUserID,
			"role_id":       roleID.String(),
			"role_name":     updatedRole.Name,
			"duration":      duration.Milliseconds(),
			"ip":            c.ClientIP(),
		})
		s.monitoring.RecordAuditEvent(ctx, "update_role", "role", adminUserID, map[string]interface{}{
			"role_id":   roleID.String(),
			"role_name": updatedRole.Name,
		})
		s.monitoring.FinishTrace(ctx, trace, nil)
	}

	s.successResponse(c, http.StatusOK, updatedRole)
}

// deleteRoleHandler deletes a role
func (s *Server) deleteRoleHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	// Start monitoring trace
	var trace *monitoring.TraceContext
	if s.monitoring != nil {
		trace, ctx = s.monitoring.StartTrace(ctx, "delete_role")
		c.Request = c.Request.WithContext(ctx)
	}

	roleIDStr, valid := s.parseUUIDParam(c, "role_id")
	if !valid {
		if s.monitoring != nil {
			err := fmt.Errorf("invalid role ID parameter")
			s.trackError(ctx, err, monitoring.ErrorCategoryValidation, "delete_role", "role")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		return
	}

	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.ErrorCategoryValidation, "delete_role", "role")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.badRequestResponse(c, "Invalid role ID format", nil)
		return
	}

	// Get admin user info for audit
	adminUserID, _, _, _ := s.getUserContext(c)

	err = s.roleService.DeleteRole(c.Request.Context(), roleID)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.ErrorCategoryService, "delete_role", "role")
			s.trackSecurityEvent(ctx, "role_deletion_failed", "high", map[string]interface{}{
				"admin_user_id": adminUserID,
				"role_id":       roleID.String(),
				"error":         err.Error(),
				"ip":            c.ClientIP(),
			})
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.handleServiceError(c, err)
		return
	}

	// Track successful role deletion
	if s.monitoring != nil {
		s.trackSecurityEvent(ctx, "role_deleted", "high", map[string]interface{}{
			"admin_user_id": adminUserID,
			"role_id":       roleID.String(),
			"duration":      duration.Milliseconds(),
			"ip":            c.ClientIP(),
		})
		s.monitoring.RecordAuditEvent(ctx, "delete_role", "role", adminUserID, map[string]interface{}{
			"role_id": roleID.String(),
		})
		s.monitoring.FinishTrace(ctx, trace, nil)
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"message": "Role deleted successfully",
	})
}

// assignRoleToUserHandler assigns a role to a user
func (s *Server) assignRoleToUserHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	// Start monitoring trace
	var trace *monitoring.TraceContext
	if s.monitoring != nil {
		trace, ctx = s.monitoring.StartTrace(ctx, "assign_role_to_user")
		c.Request = c.Request.WithContext(ctx)
	}

	roleIDStr, valid := s.parseUUIDParam(c, "role_id")
	if !valid {
		if s.monitoring != nil {
			err := fmt.Errorf("invalid role ID parameter")
			s.trackError(ctx, err, monitoring.ErrorCategoryValidation, "assign_role", "role")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		return
	}

	userIDStr, valid := s.parseUUIDParam(c, "user_id")
	if !valid {
		if s.monitoring != nil {
			err := fmt.Errorf("invalid user ID parameter")
			s.trackError(ctx, err, monitoring.ErrorCategoryValidation, "assign_role", "role")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		return
	}

	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.ErrorCategoryValidation, "assign_role", "role")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.badRequestResponse(c, "Invalid role ID format", nil)
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.ErrorCategoryValidation, "assign_role", "role")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.badRequestResponse(c, "Invalid user ID format", nil)
		return
	}

	// Get the current user (admin) who is making the assignment
	adminUserID, _, _, _ := s.getUserContext(c)
	assignedBy, err := uuid.Parse(adminUserID)
	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.ErrorCategoryAuth, "assign_role", "role")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.internalServerErrorResponse(c, "Invalid admin user ID")
		return
	}

	err = s.roleService.AssignRoleToUser(c.Request.Context(), userID, roleID, assignedBy)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.ErrorCategoryService, "assign_role", "role")
			s.trackSecurityEvent(ctx, "role_assignment_failed", "high", map[string]interface{}{
				"admin_user_id":  adminUserID,
				"target_user_id": userID.String(),
				"role_id":        roleID.String(),
				"error":          err.Error(),
				"ip":             c.ClientIP(),
			})
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.handleServiceError(c, err)
		return
	}

	// Track successful role assignment
	if s.monitoring != nil {
		s.trackSecurityEvent(ctx, "role_assigned", "high", map[string]interface{}{
			"admin_user_id":  adminUserID,
			"target_user_id": userID.String(),
			"role_id":        roleID.String(),
			"duration":       duration.Milliseconds(),
			"ip":             c.ClientIP(),
		})
		s.monitoring.RecordAuditEvent(ctx, "assign_role", "role", adminUserID, map[string]interface{}{
			"target_user_id": userID.String(),
			"role_id":        roleID.String(),
		})
		s.monitoring.FinishTrace(ctx, trace, nil)
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"message": "Role assigned to user successfully",
	})
}

// removeRoleFromUserHandler removes a role from a user
func (s *Server) removeRoleFromUserHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	// Start monitoring trace
	var trace *monitoring.TraceContext
	if s.monitoring != nil {
		trace, ctx = s.monitoring.StartTrace(ctx, "remove_role_from_user")
		c.Request = c.Request.WithContext(ctx)
	}

	roleIDStr, valid := s.parseUUIDParam(c, "role_id")
	if !valid {
		if s.monitoring != nil {
			err := fmt.Errorf("invalid role ID parameter")
			s.trackError(ctx, err, monitoring.ErrorCategoryValidation, "remove_role", "role")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		return
	}

	userIDStr, valid := s.parseUUIDParam(c, "user_id")
	if !valid {
		if s.monitoring != nil {
			err := fmt.Errorf("invalid user ID parameter")
			s.trackError(ctx, err, monitoring.ErrorCategoryValidation, "remove_role", "role")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		return
	}

	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.ErrorCategoryValidation, "remove_role", "role")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.badRequestResponse(c, "Invalid role ID format", nil)
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.ErrorCategoryValidation, "remove_role", "role")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.badRequestResponse(c, "Invalid user ID format", nil)
		return
	}

	// Get admin user info for audit
	adminUserID, _, _, _ := s.getUserContext(c)

	err = s.roleService.RemoveRoleFromUser(c.Request.Context(), userID, roleID)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.ErrorCategoryService, "remove_role", "role")
			s.trackSecurityEvent(ctx, "role_removal_failed", "high", map[string]interface{}{
				"admin_user_id":  adminUserID,
				"target_user_id": userID.String(),
				"role_id":        roleID.String(),
				"error":          err.Error(),
				"ip":             c.ClientIP(),
			})
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.handleServiceError(c, err)
		return
	}

	// Track successful role removal
	if s.monitoring != nil {
		s.trackSecurityEvent(ctx, "role_removed", "high", map[string]interface{}{
			"admin_user_id":  adminUserID,
			"target_user_id": userID.String(),
			"role_id":        roleID.String(),
			"duration":       duration.Milliseconds(),
			"ip":             c.ClientIP(),
		})
		s.monitoring.RecordAuditEvent(ctx, "remove_role", "role", adminUserID, map[string]interface{}{
			"target_user_id": userID.String(),
			"role_id":        roleID.String(),
		})
		s.monitoring.FinishTrace(ctx, trace, nil)
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"message": "Role removed from user successfully",
	})
}

// getRoleUsersHandler gets all users assigned to a role
func (s *Server) getRoleUsersHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	// Start monitoring trace
	var trace *monitoring.TraceContext
	if s.monitoring != nil {
		trace, ctx = s.monitoring.StartTrace(ctx, "get_role_users")
		c.Request = c.Request.WithContext(ctx)
	}

	roleIDStr, valid := s.parseUUIDParam(c, "role_id")
	if !valid {
		if s.monitoring != nil {
			err := fmt.Errorf("invalid role ID parameter")
			s.trackError(ctx, err, monitoring.ErrorCategoryValidation, "get_role_users", "role")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		return
	}

	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.ErrorCategoryValidation, "get_role_users", "role")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.badRequestResponse(c, "Invalid role ID format", nil)
		return
	}

	users, err := s.roleService.GetRoleUsers(c.Request.Context(), roleID)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.ErrorCategoryService, "get_role_users", "role")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.handleServiceError(c, err)
		return
	}

	// Track successful role users retrieval
	if s.monitoring != nil {
		adminUserID, _, _, _ := s.getUserContext(c)
		s.monitoring.RecordAuditEvent(ctx, "get_role_users", "role", adminUserID, map[string]interface{}{
			"role_id":    roleID.String(),
			"user_count": len(users),
			"duration":   duration.Milliseconds(),
		})
		s.monitoring.FinishTrace(ctx, trace, nil)
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"users": users,
	})
}

// ValidatePermissionRequest represents a permission validation request
type ValidatePermissionRequest struct {
	UserID     string                 `json:"user_id" validate:"required,uuid"`
	Resource   string                 `json:"resource" validate:"required"`
	Action     string                 `json:"action" validate:"required"`
	Scope      string                 `json:"scope,omitempty"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

// validatePermissionHandler validates if a user has a specific permission
func (s *Server) validatePermissionHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	// Start monitoring trace
	var trace *monitoring.TraceContext
	if s.monitoring != nil {
		trace, ctx = s.monitoring.StartTrace(ctx, "validate_permission")
		c.Request = c.Request.WithContext(ctx)
	}

	var req ValidatePermissionRequest
	if !s.bindAndValidate(c, &req) {
		if s.monitoring != nil {
			err := fmt.Errorf("invalid validate permission request")
			s.trackError(ctx, err, monitoring.ErrorCategoryValidation, "validate_permission", "role")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.ErrorCategoryValidation, "validate_permission", "role")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.badRequestResponse(c, "Invalid user ID format", nil)
		return
	}

	permission := interfaces.Permission{
		Resource:   req.Resource,
		Action:     req.Action,
		Scope:      req.Scope,
		Attributes: req.Attributes,
	}

	hasPermission, err := s.roleService.ValidatePermission(c.Request.Context(), userID, permission)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.ErrorCategoryService, "validate_permission", "role")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.handleServiceError(c, err)
		return
	}

	// Track permission validation
	if s.monitoring != nil {
		adminUserID, _, _, _ := s.getUserContext(c)
		s.trackSecurityEvent(ctx, "permission_validated", "low", map[string]interface{}{
			"admin_user_id":  adminUserID,
			"target_user_id": req.UserID,
			"resource":       req.Resource,
			"action":         req.Action,
			"scope":          req.Scope,
			"allowed":        hasPermission,
			"duration":       duration.Milliseconds(),
			"ip":             c.ClientIP(),
		})
		s.monitoring.RecordAuditEvent(ctx, "validate_permission", "role", adminUserID, map[string]interface{}{
			"target_user_id": req.UserID,
			"resource":       req.Resource,
			"action":         req.Action,
			"allowed":        hasPermission,
		})
		s.monitoring.FinishTrace(ctx, trace, nil)
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"user_id":    req.UserID,
		"permission": permission,
		"allowed":    hasPermission,
	})
}

// validateAccessHandler validates access using attribute-based access control
func (s *Server) validateAccessHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	// Start monitoring trace
	var trace *monitoring.TraceContext
	if s.monitoring != nil {
		trace, ctx = s.monitoring.StartTrace(ctx, "validate_access")
		c.Request = c.Request.WithContext(ctx)
	}

	var req interfaces.AccessRequest
	if !s.bindAndValidate(c, &req) {
		if s.monitoring != nil {
			err := fmt.Errorf("invalid validate access request")
			s.trackError(ctx, err, monitoring.ErrorCategoryValidation, "validate_access", "role")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		return
	}

	resp, err := s.roleService.ValidateAccess(c.Request.Context(), req)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.ErrorCategoryService, "validate_access", "role")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.handleServiceError(c, err)
		return
	}

	// Track access validation
	if s.monitoring != nil {
		adminUserID, _, _, _ := s.getUserContext(c)
		s.trackSecurityEvent(ctx, "access_validated", "low", map[string]interface{}{
			"admin_user_id": adminUserID,
			"user_id":       req.UserID,
			"resource":      req.Resource,
			"action":        req.Action,
			"allowed":       resp.Allowed,
			"duration":      duration.Milliseconds(),
			"ip":            c.ClientIP(),
		})
		s.monitoring.RecordAuditEvent(ctx, "validate_access", "role", adminUserID, map[string]interface{}{
			"user_id":  req.UserID,
			"resource": req.Resource,
			"action":   req.Action,
			"allowed":  resp.Allowed,
		})
		s.monitoring.FinishTrace(ctx, trace, nil)
	}

	s.successResponse(c, http.StatusOK, resp)
}
