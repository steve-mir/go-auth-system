package rest

import (
	"net/http"

	"github.com/gin-gonic/gin"
	user "github.com/steve-mir/go-auth-system/internal/service/user1"
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
	userID, _, _, _ := s.getUserContext(c)
	if userID == "" {
		s.unauthorizedResponse(c, "User ID not found in context")
		return
	}

	profile, err := s.userService.GetProfile(c.Request.Context(), userID)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, profile)
}

// updateUserProfileHandler updates the current user's profile
func (s *Server) updateUserProfileHandler(c *gin.Context) {
	userID, _, _, _ := s.getUserContext(c)
	if userID == "" {
		s.unauthorizedResponse(c, "User ID not found in context")
		return
	}

	var req user.UpdateProfileRequest
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

// changePasswordHandler handles password change requests
func (s *Server) changePasswordHandler(c *gin.Context) {
	userID, _, _, _ := s.getUserContext(c)
	if userID == "" {
		s.unauthorizedResponse(c, "User ID not found in context")
		return
	}

	var req user.ChangePasswordRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	err := s.userService.ChangePassword(c.Request.Context(), userID, &req)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"message": "Password changed successfully",
	})
}

// deleteUserAccountHandler handles user account deletion
func (s *Server) deleteUserAccountHandler(c *gin.Context) {
	userID, _, _, _ := s.getUserContext(c)
	if userID == "" {
		s.unauthorizedResponse(c, "User ID not found in context")
		return
	}

	err := s.userService.DeleteUser(c.Request.Context(), userID)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"message": "Account deleted successfully",
	})
}

// getUserRolesHandler gets the current user's roles
func (s *Server) getUserRolesHandler(c *gin.Context) {
	userID, _, _, _ := s.getUserContext(c)
	if userID == "" {
		s.unauthorizedResponse(c, "User ID not found in context")
		return
	}

	roles, err := s.userService.GetUserRoles(c.Request.Context(), userID)
	if err != nil {
		s.handleServiceError(c, err)
		return
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

	req := &user.ListUsersRequest{
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

	var req user.UpdateProfileRequest
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
