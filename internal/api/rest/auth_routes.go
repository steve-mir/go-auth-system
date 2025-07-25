package rest

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/interfaces"
	"github.com/steve-mir/go-auth-system/internal/monitoring"
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
	ctx := c.Request.Context()
	start := time.Now()

	// Start monitoring trace
	var trace *monitoring.TraceContext
	if s.monitoring != nil {
		trace, ctx = s.monitoring.StartTrace(ctx, "user_registration")
		c.Request = c.Request.WithContext(ctx)
	}

	var req interfaces.RegisterRequest
	if !s.bindAndValidate(c, &req) {
		if s.monitoring != nil {
			err := fmt.Errorf("invalid registration request")
			s.monitoring.FinishTrace(ctx, trace, err)
			s.trackError(ctx, err, monitoring.CategoryValidation, "register", "auth")
		}
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
	duration := time.Since(start)

	if err != nil {
		// Track failed registration
		if s.monitoring != nil {
			s.trackAuthEvent(ctx, "register", "", false, duration, map[string]interface{}{
				"email": req.Email,
				"error": err.Error(),
				"ip":    ipAddress,
			})
			s.trackError(ctx, err, monitoring.CategoryAuth, "register", "auth")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.handleServiceError(c, err)
		return
	}

	// Track successful registration
	if s.monitoring != nil {
		s.trackAuthEvent(ctx, "register", resp.UserID.String(), true, duration, map[string]interface{}{
			"email":    resp.Email,
			"username": req.Username,
			"ip":       ipAddress,
		})
		s.trackUserEvent(ctx, "created", resp.UserID.String(), map[string]interface{}{
			"email":    resp.Email,
			"username": req.Username,
			"method":   "registration",
		})
		s.monitoring.FinishTrace(ctx, trace, nil)
	}

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
	ctx := c.Request.Context()
	start := time.Now()

	// Start monitoring trace
	var trace *monitoring.TraceContext
	if s.monitoring != nil {
		trace, ctx = s.monitoring.StartTrace(ctx, "user_login")
		c.Request = c.Request.WithContext(ctx)
	}

	var req interfaces.LoginRequest
	if !s.bindAndValidate(c, &req) {
		if s.monitoring != nil {
			err := fmt.Errorf("invalid login request")
			s.monitoring.FinishTrace(ctx, trace, err)
			s.trackError(ctx, err, monitoring.CategoryValidation, "login", "auth")
		}
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
	duration := time.Since(start)

	if err != nil {
		// Track failed login
		if s.monitoring != nil {
			identifier := req.Email
			if identifier == "" {
				identifier = req.Username
			}
			s.trackAuthEvent(ctx, "login", "", false, duration, map[string]interface{}{
				"identifier": identifier,
				"error":      err.Error(),
				"ip":         ipAddress,
				"user_agent": userAgent,
			})
			s.trackSecurityEvent(ctx, "failed_login", "medium", map[string]interface{}{
				"identifier": identifier,
				"ip":         ipAddress,
				"error":      err.Error(),
			})
			s.trackError(ctx, err, monitoring.CategoryAuth, "login", "auth")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.handleServiceError(c, err)
		return
	}

	// Track successful login
	if s.monitoring != nil {
		s.trackAuthEvent(ctx, "login", resp.UserID.String(), true, duration, map[string]interface{}{
			"email":      resp.Email,
			"username":   resp.Username,
			"ip":         ipAddress,
			"user_agent": userAgent,
		})
		s.trackUserEvent(ctx, "login", resp.UserID.String(), map[string]interface{}{
			"email":      resp.Email,
			"username":   resp.Username,
			"ip":         ipAddress,
			"user_agent": userAgent,
		})
		s.monitoring.FinishTrace(ctx, trace, nil)
	}

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
	ctx := c.Request.Context()
	start := time.Now()

	// Start monitoring trace
	var trace *monitoring.TraceContext
	if s.monitoring != nil {
		trace, ctx = s.monitoring.StartTrace(ctx, "user_logout")
		c.Request = c.Request.WithContext(ctx)
	}

	var req interfaces.LogoutRequest
	if !s.bindAndValidate(c, &req) {
		if s.monitoring != nil {
			err := fmt.Errorf("invalid logout request")
			s.monitoring.FinishTrace(ctx, trace, err)
			s.trackError(ctx, err, monitoring.CategoryValidation, "logout", "auth")
		}
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

	// Get client info for monitoring
	ipAddress, userAgent := s.getClientInfo(c)

	// Call auth service
	err := s.authService.Logout(c.Request.Context(), &req)
	duration := time.Since(start)

	if err != nil {
		// Track failed logout
		if s.monitoring != nil {
			s.trackAuthEvent(ctx, "logout", "", false, duration, map[string]interface{}{
				"error":      err.Error(),
				"ip":         ipAddress,
				"user_agent": userAgent,
			})
			s.trackError(ctx, err, monitoring.CategoryAuth, "logout", "auth")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.handleServiceError(c, err)
		return
	}

	// Track successful logout
	if s.monitoring != nil {
		// Try to get user ID from context if available
		userID, _ := c.Get("user_id")
		userIDStr := ""
		if userID != nil {
			userIDStr = fmt.Sprintf("%v", userID)
		}

		s.trackAuthEvent(ctx, "logout", userIDStr, true, duration, map[string]interface{}{
			"ip":         ipAddress,
			"user_agent": userAgent,
		})
		s.trackUserEvent(ctx, "logout", userIDStr, map[string]interface{}{
			"ip":         ipAddress,
			"user_agent": userAgent,
		})
		s.monitoring.FinishTrace(ctx, trace, nil)
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"message": "Successfully logged out",
	})
}

// refreshTokenHandler handles token refresh
func (s *Server) refreshTokenHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	// Start monitoring trace
	var trace *monitoring.TraceContext
	if s.monitoring != nil {
		trace, ctx = s.monitoring.StartTrace(ctx, "token_refresh")
		c.Request = c.Request.WithContext(ctx)
	}

	var req interfaces.RefreshTokenRequest
	if !s.bindAndValidate(c, &req) {
		if s.monitoring != nil {
			err := fmt.Errorf("invalid refresh token request")
			s.monitoring.FinishTrace(ctx, trace, err)
			s.trackError(ctx, err, monitoring.CategoryValidation, "refresh_token", "auth")
		}
		return
	}

	// Get client info
	ipAddress, userAgent := s.getClientInfo(c)
	req.IPAddress = ipAddress
	req.UserAgent = userAgent

	// Call auth service
	resp, err := s.authService.RefreshToken(c.Request.Context(), &req)
	duration := time.Since(start)

	if err != nil {
		// Track failed token refresh
		if s.monitoring != nil {
			s.monitoring.GetMetrics().RecordTokenRefresh("failed")
			s.trackSecurityEvent(ctx, "token_refresh_failed", "medium", map[string]interface{}{
				"error":      err.Error(),
				"ip":         ipAddress,
				"user_agent": userAgent,
			})
			s.trackError(ctx, err, monitoring.CategoryAuth, "refresh_token", "auth")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.handleServiceError(c, err)
		return
	}

	// Track successful token refresh
	if s.monitoring != nil {
		s.monitoring.GetMetrics().RecordTokenRefresh("success")
		s.monitoring.RecordTokenEvent(ctx, "refresh", "access_token", true, map[string]interface{}{
			"ip":         ipAddress,
			"user_agent": userAgent,
			"duration":   duration.Milliseconds(),
		})
		s.monitoring.FinishTrace(ctx, trace, nil)
	}

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
	ctx := c.Request.Context()
	start := time.Now()

	// Start monitoring trace
	var trace *monitoring.TraceContext
	if s.monitoring != nil {
		trace, ctx = s.monitoring.StartTrace(ctx, "token_validation")
		c.Request = c.Request.WithContext(ctx)
	}

	var req interfaces.ValidateTokenRequest
	if !s.bindAndValidate(c, &req) {
		if s.monitoring != nil {
			err := fmt.Errorf("invalid token validation request")
			s.monitoring.FinishTrace(ctx, trace, err)
			s.trackError(ctx, err, monitoring.CategoryValidation, "validate_token", "auth")
		}
		return
	}

	// Get client info for monitoring
	ipAddress, userAgent := s.getClientInfo(c)

	// Call auth service
	resp, err := s.authService.ValidateToken(c.Request.Context(), &req)
	duration := time.Since(start)

	if err != nil {
		// Track failed token validation
		if s.monitoring != nil {
			s.monitoring.GetMetrics().RecordTokenValidation("access_token", "failed")
			s.trackSecurityEvent(ctx, "token_validation_failed", "low", map[string]interface{}{
				"error":      err.Error(),
				"ip":         ipAddress,
				"user_agent": userAgent,
			})
			s.trackError(ctx, err, monitoring.CategoryAuth, "validate_token", "auth")
			s.monitoring.FinishTrace(ctx, trace, err)
		}
		s.handleServiceError(c, err)
		return
	}

	// Track successful token validation
	if s.monitoring != nil {
		s.monitoring.GetMetrics().RecordTokenValidation("access_token", "success")
		s.monitoring.RecordTokenEvent(ctx, "validate", "access_token", true, map[string]interface{}{
			"user_id":    resp.UserID,
			"valid":      resp.Valid,
			"ip":         ipAddress,
			"user_agent": userAgent,
			"duration":   duration.Milliseconds(),
		})
		s.monitoring.FinishTrace(ctx, trace, nil)
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
