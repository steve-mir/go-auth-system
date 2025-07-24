package rest

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/interfaces"
	"github.com/steve-mir/go-auth-system/internal/monitoring"
	// "github.com/steve-mir/go-auth-system/internal/service/user"
)

// setupUserRoutes configures user management routes
func (s *Server) setupUserRoutes(group *gin.RouterGroup) {
	group.GET("/profile", s.getUserProfileHandler)
	group.PUT("/profile", s.updateUserProfileHandler)
	group.POST("/change-password", s.changePasswordHandler)
	group.DELETE("/account", s.deleteUserAccountHandler)
	group.GET("/roles", s.getUserRolesHandler)

	// Admin-only user management routes
	adminGroup := group.Group("")
	adminGroup.Use(s.adminAuthorizationMiddleware())
	{
		adminGroup.GET("", s.listUsersHandler)
		adminGroup.GET("/:user_id", s.getUserByIDHandler)
		adminGroup.PUT("/:user_id", s.updateUserByIDHandler)
		adminGroup.DELETE("/:user_id", s.deleteUserByIDHandler)
	}
}

// getUserProfileHandler gets the current user's profile
func (s *Server) getUserProfileHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	// Start monitoring trace
	var trace *monitoring.TraceContext
	if s.monitoring != nil {
		trace, ctx = s.monitoring.StartTrace(ctx, "get_user_profile")
		c.Request = c.Request.WithContext(ctx)
	}

	userID, _, _, _ := s.getUserContext(c)
	if userID == "" {
		if s.monitoring != nil {
			err := fmt.Errorf("user ID not found in context")
			s.trackError(ctx, err, monitoring.ErrorCategoryAuth, "get_profile", "user")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.unauthorizedResponse(c, "User ID not found in context")
		return
	}

	profile, err := s.userService.GetProfile(c.Request.Context(), userID)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.ErrorCategoryService, "get_profile", "user")
			s.trackUserEvent(ctx, "profile_access_failed", userID, map[string]interface{}{
				"error":    err.Error(),
				"duration": duration.Milliseconds(),
			})
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.handleServiceError(c, err)
		return
	}

	// Track successful profile access
	if s.monitoring != nil {
		s.trackUserEvent(ctx, "profile_accessed", userID, map[string]interface{}{
			"duration": duration.Milliseconds(),
		})
		s.monitoring.FinishTrace(ctx, trace, nil)
	}

	s.successResponse(c, http.StatusOK, profile)
}

// updateUserProfileHandler updates the current user's profile
func (s *Server) updateUserProfileHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	// Start monitoring trace
	var trace *monitoring.TraceContext
	if s.monitoring != nil {
		trace, ctx = s.monitoring.StartTrace(ctx, "update_user_profile")
		c.Request = c.Request.WithContext(ctx)
	}

	userID, _, _, _ := s.getUserContext(c)
	if userID == "" {
		if s.monitoring != nil {
			err := fmt.Errorf("user ID not found in context")
			s.trackError(ctx, err, monitoring.ErrorCategoryAuth, "update_profile", "user")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.unauthorizedResponse(c, "User ID not found in context")
		return
	}

	var req interfaces.UpdateProfileRequest
	if !s.bindAndValidate(c, &req) {
		if s.monitoring != nil {
			err := fmt.Errorf("invalid update profile request")
			s.trackError(ctx, err, monitoring.ErrorCategoryValidation, "update_profile", "user")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		return
	}

	// Sanitize input
	if req.FirstName != nil {
		sanitizeStringField(req.FirstName)
	}
	if req.LastName != nil {
		sanitizeStringField(req.LastName)
	}
	if req.Phone != nil {
		sanitizeStringField(req.Phone)
	}

	profile, err := s.userService.UpdateProfile(c.Request.Context(), userID, &req)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.ErrorCategoryService, "update_profile", "user")
			s.trackUserEvent(ctx, "profile_update_failed", userID, map[string]interface{}{
				"error":    err.Error(),
				"duration": duration.Milliseconds(),
			})
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.handleServiceError(c, err)
		return
	}

	// Track successful profile update
	if s.monitoring != nil {
		s.monitoring.GetMetrics().RecordProfileUpdate("profile")
		s.trackUserEvent(ctx, "profile_updated", userID, map[string]interface{}{
			"duration":       duration.Milliseconds(),
			"fields_updated": getUpdatedFields(&req),
		})
		s.monitoring.FinishTrace(ctx, trace, nil)
	}

	s.successResponse(c, http.StatusOK, profile)
}

// changePasswordHandler handles password change requests
func (s *Server) changePasswordHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	// Start monitoring trace
	var trace *monitoring.TraceContext
	if s.monitoring != nil {
		trace, ctx = s.monitoring.StartTrace(ctx, "change_password")
		c.Request = c.Request.WithContext(ctx)
	}

	userID, _, _, _ := s.getUserContext(c)
	if userID == "" {
		if s.monitoring != nil {
			err := fmt.Errorf("user ID not found in context")
			s.trackError(ctx, err, monitoring.ErrorCategoryAuth, "change_password", "user")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.unauthorizedResponse(c, "User ID not found in context")
		return
	}

	var req interfaces.ChangePasswordRequest
	if !s.bindAndValidate(c, &req) {
		if s.monitoring != nil {
			err := fmt.Errorf("invalid change password request")
			s.trackError(ctx, err, monitoring.ErrorCategoryValidation, "change_password", "user")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		return
	}

	err := s.userService.ChangePassword(c.Request.Context(), userID, &req)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.ErrorCategoryService, "change_password", "user")
			s.trackSecurityEvent(ctx, "password_change_failed", "medium", map[string]interface{}{
				"user_id": userID,
				"error":   err.Error(),
				"ip":      c.ClientIP(),
			})
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.handleServiceError(c, err)
		return
	}

	// Track successful password change
	if s.monitoring != nil {
		s.trackSecurityEvent(ctx, "password_changed", "low", map[string]interface{}{
			"user_id":  userID,
			"duration": duration.Milliseconds(),
			"ip":       c.ClientIP(),
		})
		s.trackUserEvent(ctx, "password_changed", userID, map[string]interface{}{
			"duration": duration.Milliseconds(),
		})
		s.monitoring.FinishTrace(ctx, trace, nil)
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"message": "Password changed successfully",
	})
}

// deleteUserAccountHandler handles user account deletion
func (s *Server) deleteUserAccountHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	// Start monitoring trace
	var trace *monitoring.TraceContext
	if s.monitoring != nil {
		trace, ctx = s.monitoring.StartTrace(ctx, "delete_user_account")
		c.Request = c.Request.WithContext(ctx)
	}

	userID, _, _, _ := s.getUserContext(c)
	if userID == "" {
		if s.monitoring != nil {
			err := fmt.Errorf("user ID not found in context")
			s.trackError(ctx, err, monitoring.ErrorCategoryAuth, "delete_account", "user")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.unauthorizedResponse(c, "User ID not found in context")
		return
	}

	err := s.userService.DeleteUser(c.Request.Context(), userID)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.ErrorCategoryService, "delete_account", "user")
			s.trackSecurityEvent(ctx, "account_deletion_failed", "medium", map[string]interface{}{
				"user_id": userID,
				"error":   err.Error(),
				"ip":      c.ClientIP(),
			})
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.handleServiceError(c, err)
		return
	}

	// Track successful account deletion
	if s.monitoring != nil {
		s.trackSecurityEvent(ctx, "account_deleted", "high", map[string]interface{}{
			"user_id":  userID,
			"duration": duration.Milliseconds(),
			"ip":       c.ClientIP(),
		})
		s.trackUserEvent(ctx, "account_deleted", userID, map[string]interface{}{
			"duration": duration.Milliseconds(),
		})
		s.monitoring.FinishTrace(ctx, trace, nil)
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"message": "Account deleted successfully",
	})
}

// getUserRolesHandler gets the current user's roles
func (s *Server) getUserRolesHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	// Start monitoring trace
	var trace *monitoring.TraceContext
	if s.monitoring != nil {
		trace, ctx = s.monitoring.StartTrace(ctx, "get_user_roles")
		c.Request = c.Request.WithContext(ctx)
	}

	userID, _, _, _ := s.getUserContext(c)
	if userID == "" {
		if s.monitoring != nil {
			err := fmt.Errorf("user ID not found in context")
			s.trackError(ctx, err, monitoring.ErrorCategoryAuth, "get_roles", "user")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.unauthorizedResponse(c, "User ID not found in context")
		return
	}

	roles, err := s.userService.GetUserRoles(c.Request.Context(), userID)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.ErrorCategoryService, "get_roles", "user")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.handleServiceError(c, err)
		return
	}

	// Track successful roles access
	if s.monitoring != nil {
		s.trackUserEvent(ctx, "roles_accessed", userID, map[string]interface{}{
			"duration":   duration.Milliseconds(),
			"role_count": len(roles),
		})
		s.monitoring.FinishTrace(ctx, trace, nil)
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"roles": roles,
	})
}

// Admin-only handlers

// listUsersHandler lists all users with pagination
func (s *Server) listUsersHandler(c *gin.Context) {
	page, limit, valid := s.GetPaginationParams(c)
	if !valid {
		return
	}

	search, _, valid := s.GetFilterParams(c)
	if !valid {
		return
	}

	sortBy, sortOrder, valid := s.GetSortParams(c, []string{"email", "username", "created_at", "updated_at"})
	if !valid {
		return
	}

	req := &interfaces.ListUsersRequest{
		Page:     int32(page),
		PageSize: int32(limit),
		Search:   search,
		SortBy:   sortBy,
		SortDesc: sortOrder == "desc",
	}

	resp, err := s.userService.ListUsers(c.Request.Context(), req)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	pagination := calculatePagination(page, limit, resp.Total)
	s.paginatedResponse(c, http.StatusOK, resp.Users, pagination)
}

// getUserByIDHandler gets a user by ID (admin only)
func (s *Server) getUserByIDHandler(c *gin.Context) {
	userID, valid := s.parseUUIDParam(c, "user_id")
	if !valid {
		return
	}

	profile, err := s.userService.GetProfile(c.Request.Context(), userID)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, profile)
}

// updateUserByIDHandler updates a user by ID (admin only)
func (s *Server) updateUserByIDHandler(c *gin.Context) {
	userID, valid := s.parseUUIDParam(c, "user_id")
	if !valid {
		return
	}

	var req interfaces.UpdateProfileRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	// Sanitize input
	if req.FirstName != nil {
		sanitizeStringField(req.FirstName)
	}
	if req.LastName != nil {
		sanitizeStringField(req.LastName)
	}
	if req.Phone != nil {
		sanitizeStringField(req.Phone)
	}

	profile, err := s.userService.UpdateProfile(c.Request.Context(), userID, &req)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, profile)
}

// deleteUserByIDHandler deletes a user by ID (admin only)
func (s *Server) deleteUserByIDHandler(c *gin.Context) {
	userID, valid := s.parseUUIDParam(c, "user_id")
	if !valid {
		return
	}

	err := s.userService.DeleteUser(c.Request.Context(), userID)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"message": "User deleted successfully",
	})
}
