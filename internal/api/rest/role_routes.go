package rest

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/steve-mir/go-auth-system/internal/interfaces"
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
	var req interfaces.CreateRoleRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	// Sanitize input
	sanitizeStringField(&req.Name)
	sanitizeStringField(&req.Description)

	createdRole, err := s.roleService.CreateRole(c.Request.Context(), req)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusCreated, createdRole)
}

// listRolesHandler lists all roles with pagination
func (s *Server) listRolesHandler(c *gin.Context) {
	page, limit, valid := s.GetPaginationParams(c)
	if !valid {
		return
	}

	req := interfaces.ListRolesRequest{
		Limit:  limit,
		Offset: (page - 1) * limit,
	}

	resp, err := s.roleService.ListRoles(c.Request.Context(), req)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	pagination := calculatePagination(page, limit, resp.Total)
	s.paginatedResponse(c, http.StatusOK, resp.Roles, pagination)
}

// getRoleHandler gets a role by ID
func (s *Server) getRoleHandler(c *gin.Context) {
	roleIDStr, valid := s.parseUUIDParam(c, "role_id")
	if !valid {
		return
	}

	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		s.badRequestResponse(c, "Invalid role ID format", nil)
		return
	}

	roleData, err := s.roleService.GetRole(c.Request.Context(), roleID)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, roleData)
}

// updateRoleHandler updates a role
func (s *Server) updateRoleHandler(c *gin.Context) {
	roleIDStr, valid := s.parseUUIDParam(c, "role_id")
	if !valid {
		return
	}

	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		s.badRequestResponse(c, "Invalid role ID format", nil)
		return
	}

	var req interfaces.UpdateRoleRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	// Sanitize input
	if req.Name != nil {
		sanitizeStringField(req.Name)
	}
	if req.Description != nil {
		sanitizeStringField(req.Description)
	}

	updatedRole, err := s.roleService.UpdateRole(c.Request.Context(), roleID, req)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, updatedRole)
}

// deleteRoleHandler deletes a role
func (s *Server) deleteRoleHandler(c *gin.Context) {
	roleIDStr, valid := s.parseUUIDParam(c, "role_id")
	if !valid {
		return
	}

	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		s.badRequestResponse(c, "Invalid role ID format", nil)
		return
	}

	err = s.roleService.DeleteRole(c.Request.Context(), roleID)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"message": "Role deleted successfully",
	})
}

// assignRoleToUserHandler assigns a role to a user
func (s *Server) assignRoleToUserHandler(c *gin.Context) {
	roleIDStr, valid := s.parseUUIDParam(c, "role_id")
	if !valid {
		return
	}

	userIDStr, valid := s.parseUUIDParam(c, "user_id")
	if !valid {
		return
	}

	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		s.badRequestResponse(c, "Invalid role ID format", nil)
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		s.badRequestResponse(c, "Invalid user ID format", nil)
		return
	}

	// Get the current user (admin) who is making the assignment
	adminUserID, _, _, _ := s.getUserContext(c)
	assignedBy, err := uuid.Parse(adminUserID)
	if err != nil {
		s.internalServerErrorResponse(c, "Invalid admin user ID")
		return
	}

	err = s.roleService.AssignRoleToUser(c.Request.Context(), userID, roleID, assignedBy)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"message": "Role assigned to user successfully",
	})
}

// removeRoleFromUserHandler removes a role from a user
func (s *Server) removeRoleFromUserHandler(c *gin.Context) {
	roleIDStr, valid := s.parseUUIDParam(c, "role_id")
	if !valid {
		return
	}

	userIDStr, valid := s.parseUUIDParam(c, "user_id")
	if !valid {
		return
	}

	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		s.badRequestResponse(c, "Invalid role ID format", nil)
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		s.badRequestResponse(c, "Invalid user ID format", nil)
		return
	}

	err = s.roleService.RemoveRoleFromUser(c.Request.Context(), userID, roleID)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"message": "Role removed from user successfully",
	})
}

// getRoleUsersHandler gets all users assigned to a role
func (s *Server) getRoleUsersHandler(c *gin.Context) {
	roleIDStr, valid := s.parseUUIDParam(c, "role_id")
	if !valid {
		return
	}

	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		s.badRequestResponse(c, "Invalid role ID format", nil)
		return
	}

	users, err := s.roleService.GetRoleUsers(c.Request.Context(), roleID)
	if err != nil {
		s.handleServiceError(c, err)
		return
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
	var req ValidatePermissionRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
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
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"user_id":    req.UserID,
		"permission": permission,
		"allowed":    hasPermission,
	})
}

// validateAccessHandler validates access using attribute-based access control
func (s *Server) validateAccessHandler(c *gin.Context) {
	var req interfaces.AccessRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	resp, err := s.roleService.ValidateAccess(c.Request.Context(), req)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, resp)
}
