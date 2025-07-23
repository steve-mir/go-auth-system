package rest

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/service/auth"
)

// setupAuthRoutes configures authentication routes
func (s *Server) setupAuthRoutes(group *gin.RouterGroup) {
	group.POST("/register", s.registerHandler)
	group.POST("/login", s.loginHandler)
	group.POST("/logout", s.logoutHandler)
	group.POST("/refresh", s.refreshTokenHandler)
	group.POST("/validate", s.validateTokenHandler)
}

// registerHandler handles user registration
func (s *Server) registerHandler(c *gin.Context) {
	var req auth.RegisterRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	// Sanitize input
	sanitizeStringField(&req.Email)
	sanitizeStringField(&req.Username)
	sanitizeStringField(&req.FirstName)
	sanitizeStringField(&req.LastName)
	sanitizeStringField(&req.Phone)

	// Get client info
	ipAddress, userAgent := s.getClientInfo(c)
	req.IPAddress = ipAddress
	req.UserAgent = userAgent

	// Call auth service
	resp, err := s.authService.Register(c.Request.Context(), &req)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	// Log successful registration (in production, use proper audit logging)
	// TODO: Add audit logging

	s.successResponse(c, http.StatusCreated, gin.H{
		"user_id":    resp.UserID,
		"email":      resp.Email,
		"username":   resp.Username,
		"created_at": resp.CreatedAt,
		"message":    resp.Message,
	})
}

// loginHandler handles user login
func (s *Server) loginHandler(c *gin.Context) {
	var req auth.LoginRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	// Sanitize input
	sanitizeStringField(&req.Email)
	sanitizeStringField(&req.Username)

	// Get client info
	ipAddress, userAgent := s.getClientInfo(c)
	req.IPAddress = ipAddress
	req.UserAgent = userAgent

	// Call auth service
	resp, err := s.authService.Login(c.Request.Context(), &req)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	// Log successful login (in production, use proper audit logging)
	// TODO: Add audit logging

	s.successResponse(c, http.StatusOK, gin.H{
		"user_id":       resp.UserID,
		"email":         resp.Email,
		"username":      resp.Username,
		"access_token":  resp.AccessToken,
		"refresh_token": resp.RefreshToken,
		"token_type":    resp.TokenType,
		"expires_in":    resp.ExpiresIn,
		"expires_at":    resp.ExpiresAt,
	})
}

// logoutHandler handles user logout
func (s *Server) logoutHandler(c *gin.Context) {
	var req auth.LogoutRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	// If no tokens provided in body, try to get from headers
	if req.AccessToken == "" && req.RefreshToken == "" {
		if authHeader := c.GetHeader("Authorization"); authHeader != "" {
			if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
				req.AccessToken = authHeader[7:]
			}
		}
	}

	// Call auth service
	err := s.authService.Logout(c.Request.Context(), &req)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	// Log successful logout (in production, use proper audit logging)
	// TODO: Add audit logging

	s.successResponse(c, http.StatusOK, gin.H{
		"message": "Successfully logged out",
	})
}

// refreshTokenHandler handles token refresh
func (s *Server) refreshTokenHandler(c *gin.Context) {
	var req auth.RefreshTokenRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	// Get client info
	ipAddress, userAgent := s.getClientInfo(c)
	req.IPAddress = ipAddress
	req.UserAgent = userAgent

	// Call auth service
	resp, err := s.authService.RefreshToken(c.Request.Context(), &req)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	// Log successful token refresh (in production, use proper audit logging)
	// TODO: Add audit logging

	s.successResponse(c, http.StatusOK, gin.H{
		"access_token":  resp.AccessToken,
		"refresh_token": resp.RefreshToken,
		"token_type":    resp.TokenType,
		"expires_in":    resp.ExpiresIn,
		"expires_at":    resp.ExpiresAt,
	})
}

// validateTokenHandler handles token validation
func (s *Server) validateTokenHandler(c *gin.Context) {
	var req auth.ValidateTokenRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	// Call auth service
	resp, err := s.authService.ValidateToken(c.Request.Context(), &req)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"valid":      resp.Valid,
		"user_id":    resp.UserID,
		"email":      resp.Email,
		"username":   resp.Username,
		"roles":      resp.Roles,
		"expires_at": resp.ExpiresAt,
		"metadata":   resp.Metadata,
		"claims":     resp.Claims,
	})
}
