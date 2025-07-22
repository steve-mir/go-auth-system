package rest

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// setupOAuthRoutes configures OAuth social authentication routes
func (s *Server) setupOAuthRoutes(group *gin.RouterGroup) {
	oauth := group.Group("/oauth")
	{
		oauth.GET("/:provider", s.oauthInitiateHandler)
		oauth.GET("/:provider/callback", s.oauthCallbackHandler)
		oauth.POST("/link/:provider", s.requireAuth(), s.linkSocialAccountHandler)
		oauth.DELETE("/unlink/:provider", s.requireAuth(), s.unlinkSocialAccountHandler)
		oauth.GET("/linked", s.requireAuth(), s.getLinkedAccountsHandler)
	}
}

// oauthInitiateHandler initiates OAuth flow
func (s *Server) oauthInitiateHandler(c *gin.Context) {
	provider := c.Param("provider")

	// Validate provider
	if !isValidProvider(provider) {
		s.errorResponse(c, http.StatusBadRequest, "INVALID_PROVIDER", "Invalid OAuth provider", gin.H{
			"provider":        provider,
			"valid_providers": []string{"google", "facebook", "github"},
		})
		return
	}

	// Generate OAuth URL
	authURL, err := s.ssoService.GetOAuthURL(c.Request.Context(), provider, "")
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"auth_url": authURL,
		"provider": provider,
	})
}

// oauthCallbackHandler handles OAuth callback
func (s *Server) oauthCallbackHandler(c *gin.Context) {
	provider := c.Param("provider")
	code := c.Query("code")
	state := c.Query("state")

	// Validate parameters
	if code == "" {
		s.errorResponse(c, http.StatusBadRequest, "MISSING_CODE", "Authorization code is required", nil)
		return
	}

	if state == "" {
		s.errorResponse(c, http.StatusBadRequest, "MISSING_STATE", "State parameter is required", nil)
		return
	}

	// Handle OAuth callback
	result, err := s.ssoService.HandleOAuthCallback(c.Request.Context(), provider, code, state)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	// If this is a new user, we might want to redirect to a welcome page
	// If this is an existing user, redirect to the main application

	// For API response, return the authentication result
	s.successResponse(c, http.StatusOK, gin.H{
		"user_id":       result.UserID,
		"email":         result.Email,
		"name":          result.Name,
		"provider":      result.Provider,
		"is_new_user":   result.IsNewUser,
		"access_token":  result.AccessToken,
		"refresh_token": result.RefreshToken,
		"expires_at":    result.ExpiresAt,
		"metadata":      result.Metadata,
	})
}

// linkSocialAccountHandler links a social account to the current user
func (s *Server) linkSocialAccountHandler(c *gin.Context) {
	provider := c.Param("provider")

	// Get user ID from context (set by auth middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		s.errorResponse(c, http.StatusUnauthorized, "UNAUTHORIZED", "User not authenticated", nil)
		return
	}

	userIDStr, ok := userID.(string)
	if !ok {
		s.errorResponse(c, http.StatusInternalServerError, "INVALID_USER_ID", "Invalid user ID format", nil)
		return
	}

	// Validate provider
	if !isValidProvider(provider) {
		s.errorResponse(c, http.StatusBadRequest, "INVALID_PROVIDER", "Invalid OAuth provider", gin.H{
			"provider":        provider,
			"valid_providers": []string{"google", "facebook", "github"},
		})
		return
	}

	// Generate OAuth URL for linking
	authURL, err := s.ssoService.GetOAuthURL(c.Request.Context(), provider, "")
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"auth_url": authURL,
		"provider": provider,
		"message":  "Complete OAuth flow to link account",
	})
}

// unlinkSocialAccountHandler unlinks a social account from the current user
func (s *Server) unlinkSocialAccountHandler(c *gin.Context) {
	provider := c.Param("provider")

	// Get user ID from context (set by auth middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		s.errorResponse(c, http.StatusUnauthorized, "UNAUTHORIZED", "User not authenticated", nil)
		return
	}

	userIDStr, ok := userID.(string)
	if !ok {
		s.errorResponse(c, http.StatusInternalServerError, "INVALID_USER_ID", "Invalid user ID format", nil)
		return
	}

	// Validate provider
	if !isValidProvider(provider) {
		s.errorResponse(c, http.StatusBadRequest, "INVALID_PROVIDER", "Invalid OAuth provider", gin.H{
			"provider":        provider,
			"valid_providers": []string{"google", "facebook", "github"},
		})
		return
	}

	// Unlink social account
	err := s.ssoService.UnlinkSocialAccount(c.Request.Context(), userIDStr, provider)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"message":  "Social account unlinked successfully",
		"provider": provider,
	})
}

// getLinkedAccountsHandler returns all linked social accounts for the current user
func (s *Server) getLinkedAccountsHandler(c *gin.Context) {
	// Get user ID from context (set by auth middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		s.errorResponse(c, http.StatusUnauthorized, "UNAUTHORIZED", "User not authenticated", nil)
		return
	}

	userIDStr, ok := userID.(string)
	if !ok {
		s.errorResponse(c, http.StatusInternalServerError, "INVALID_USER_ID", "Invalid user ID format", nil)
		return
	}

	// Get linked accounts
	accounts, err := s.ssoService.GetLinkedAccounts(c.Request.Context(), userIDStr)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"accounts": accounts,
		"count":    len(accounts),
	})
}

// isValidProvider checks if the provider is supported
func isValidProvider(provider string) bool {
	validProviders := map[string]bool{
		"google":   true,
		"facebook": true,
		"github":   true,
	}
	return validProviders[provider]
}
