package rest

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/interfaces"
)

// authenticationMiddleware validates JWT tokens and sets user context
func (s *Server) authenticationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			s.unauthorizedResponse(c, "Authorization header is required")
			c.Abort()
			return
		}

		// Check Bearer token format
		if !strings.HasPrefix(authHeader, "Bearer ") {
			s.unauthorizedResponse(c, "Authorization header must be in format 'Bearer <token>'")
			c.Abort()
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" {
			s.unauthorizedResponse(c, "Token is required")
			c.Abort()
			return
		}

		// Validate token using auth service
		validateReq := &interfaces.ValidateTokenRequest{
			Token: token,
		}

		validateResp, err := s.authService.ValidateToken(c.Request.Context(), validateReq)
		if err != nil {
			s.unauthorizedResponse(c, "Token validation failed")
			c.Abort()
			return
		}

		if !validateResp.Valid {
			s.unauthorizedResponse(c, "Token is invalid or expired")
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
			s.forbiddenResponse(c, "User roles not found in context")
			c.Abort()
			return
		}

		userRoles, ok := roles.([]string)
		if !ok {
			s.forbiddenResponse(c, "Invalid roles format in context")
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
			s.forbiddenResponse(c, "Admin role required")
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
			s.forbiddenResponse(c, "User roles not found in context")
			c.Abort()
			return
		}

		userRoles, ok := roles.([]string)
		if !ok {
			s.forbiddenResponse(c, "Invalid roles format in context")
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
			s.forbiddenResponse(c, "Required role not found")
			c.Abort()
			return
		}

		c.Next()
	}
}
