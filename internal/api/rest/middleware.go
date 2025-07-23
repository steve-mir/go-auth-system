package rest

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/service/auth"
)

// authenticationMiddleware validates JWT tokens and sets user context
func (s *Server) authenticationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			s.errorResponse(c, http.StatusUnauthorized, "MISSING_AUTH_HEADER", "Authorization header is required", nil)
			c.Abort()
			return
		}

		// Check Bearer token format
		if !strings.HasPrefix(authHeader, "Bearer ") {
			s.errorResponse(c, http.StatusUnauthorized, "INVALID_AUTH_FORMAT", "Authorization header must be in format 'Bearer <token>'", nil)
			c.Abort()
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" {
			s.errorResponse(c, http.StatusUnauthorized, "MISSING_TOKEN", "Token is required", nil)
			c.Abort()
			return
		}

		// Validate token using auth service
		validateReq := &auth.ValidateTokenRequest{
			Token: token,
		}

		validateResp, err := s.authService.ValidateToken(c.Request.Context(), validateReq)
		if err != nil {
			s.errorResponse(c, http.StatusUnauthorized, "INVALID_TOKEN", "Token validation failed", map[string]interface{}{
				"error": err.Error(),
			})
			c.Abort()
			return
		}

		if !validateResp.Valid {
			s.errorResponse(c, http.StatusUnauthorized, "TOKEN_INVALID", "Token is invalid or expired", nil)
			c.Abort()
			return
		}

		// Set user context
		c.Set("user_id", validateResp.UserID)
		c.Set("user_email", validateResp.Email)
		c.Set("user_username", validateResp.Username)
		c.Set("user_roles", validateResp.Roles)
		c.Set("token", token)
		c.Set("token_claims", validateResp.Claims)

		c.Next()
	}
}

// adminAuthorizationMiddleware checks if user has admin role
func (s *Server) adminAuthorizationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		roles, exists := c.Get("user_roles")
		if !exists {
			s.errorResponse(c, http.StatusForbidden, "NO_ROLES", "User roles not found in context", nil)
			c.Abort()
			return
		}

		userRoles, ok := roles.([]string)
		if !ok {
			s.errorResponse(c, http.StatusForbidden, "INVALID_ROLES", "Invalid roles format in context", nil)
			c.Abort()
			return
		}

		// Check if user has admin role
		hasAdminRole := false
		for _, role := range userRoles {
			if role == "admin" || role == "administrator" || role == "super_admin" {
				hasAdminRole = true
				break
			}
		}

		if !hasAdminRole {
			s.errorResponse(c, http.StatusForbidden, "INSUFFICIENT_PERMISSIONS", "Admin role required", nil)
			c.Abort()
			return
		}

		c.Next()
	}
}

// roleAuthorizationMiddleware checks if user has any of the required roles
func (s *Server) roleAuthorizationMiddleware(requiredRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		roles, exists := c.Get("user_roles")
		if !exists {
			s.errorResponse(c, http.StatusForbidden, "NO_ROLES", "User roles not found in context", nil)
			c.Abort()
			return
		}

		userRoles, ok := roles.([]string)
		if !ok {
			s.errorResponse(c, http.StatusForbidden, "INVALID_ROLES", "Invalid roles format in context", nil)
			c.Abort()
			return
		}

		// Check if user has any of the required roles
		hasRequiredRole := false
		for _, userRole := range userRoles {
			for _, requiredRole := range requiredRoles {
				if userRole == requiredRole {
					hasRequiredRole = true
					break
				}
			}
			if hasRequiredRole {
				break
			}
		}

		if !hasRequiredRole {
			s.errorResponse(c, http.StatusForbidden, "INSUFFICIENT_PERMISSIONS", "Required role not found", map[string]interface{}{
				"required_roles": requiredRoles,
				"user_roles":     userRoles,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// getUserContext extracts user information from gin context
func (s *Server) getUserContext(c *gin.Context) (userID, email, username string, roles []string) {
	if id, exists := c.Get("user_id"); exists {
		userID, _ = id.(string)
	}
	if e, exists := c.Get("user_email"); exists {
		email, _ = e.(string)
	}
	if u, exists := c.Get("user_username"); exists {
		username, _ = u.(string)
	}
	if r, exists := c.Get("user_roles"); exists {
		roles, _ = r.([]string)
	}
	return
}

// getClientInfo extracts client information from request
func (s *Server) getClientInfo(c *gin.Context) (ipAddress, userAgent string) {
	// Get IP address (consider X-Forwarded-For for load balancers)
	ipAddress = c.ClientIP()
	if forwarded := c.GetHeader("X-Forwarded-For"); forwarded != "" {
		// Take the first IP in the chain
		if idx := strings.Index(forwarded, ","); idx != -1 {
			ipAddress = strings.TrimSpace(forwarded[:idx])
		} else {
			ipAddress = strings.TrimSpace(forwarded)
		}
	}

	userAgent = c.GetHeader("User-Agent")
	return
}
