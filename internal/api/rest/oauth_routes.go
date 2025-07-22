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

	// SAML 2.0 routes
	saml := group.Group("/saml")
	{
		saml.GET("/metadata", s.samlMetadataHandler)
		saml.POST("/login", s.samlInitiateHandler)
		saml.POST("/acs", s.samlAssertionConsumerHandler)
		saml.POST("/slo", s.samlSingleLogoutHandler)
	}

	// OpenID Connect routes
	oidc := group.Group("/oidc")
	{
		oidc.GET("/:provider", s.oidcInitiateHandler)
		oidc.GET("/:provider/callback", s.oidcCallbackHandler)
		oidc.POST("/token/validate", s.oidcValidateTokenHandler)
		oidc.POST("/token/refresh", s.oidcRefreshTokenHandler)
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

// SAML 2.0 handlers

// samlMetadataHandler returns SAML Service Provider metadata
func (s *Server) samlMetadataHandler(c *gin.Context) {
	metadata, err := s.ssoService.GetSAMLMetadata(c.Request.Context())
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	c.Header("Content-Type", "application/samlmetadata+xml")
	c.Data(http.StatusOK, "application/samlmetadata+xml", metadata)
}

// samlInitiateHandler initiates SAML authentication
func (s *Server) samlInitiateHandler(c *gin.Context) {
	var req struct {
		IDPEntityID string `json:"idp_entity_id" binding:"required"`
		RelayState  string `json:"relay_state,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		s.errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request format", gin.H{
			"error": err.Error(),
		})
		return
	}

	// Initiate SAML login
	authRequest, err := s.ssoService.InitiateSAMLLogin(c.Request.Context(), req.IDPEntityID, req.RelayState)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"auth_url":      authRequest.URL,
		"request_id":    authRequest.ID,
		"relay_state":   authRequest.RelayState,
		"idp_entity_id": authRequest.IDPEntityID,
		"created_at":    authRequest.CreatedAt,
	})
}

// samlAssertionConsumerHandler handles SAML assertion consumer service (ACS)
func (s *Server) samlAssertionConsumerHandler(c *gin.Context) {
	// SAML responses can come as form data or JSON
	var samlResponse, relayState string

	// Try to get from form data first (standard SAML POST binding)
	if c.Request.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		samlResponse = c.PostForm("SAMLResponse")
		relayState = c.PostForm("RelayState")
	} else {
		// Try JSON format
		var req struct {
			SAMLResponse string `json:"saml_response" binding:"required"`
			RelayState   string `json:"relay_state,omitempty"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			s.errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request format", gin.H{
				"error": err.Error(),
			})
			return
		}

		samlResponse = req.SAMLResponse
		relayState = req.RelayState
	}

	if samlResponse == "" {
		s.errorResponse(c, http.StatusBadRequest, "MISSING_SAML_RESPONSE", "SAML response is required", nil)
		return
	}

	// Handle SAML response
	result, err := s.ssoService.HandleSAMLResponse(c.Request.Context(), samlResponse, relayState)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	// Return authentication result
	s.successResponse(c, http.StatusOK, gin.H{
		"user_id":       result.UserID,
		"email":         result.Email,
		"name":          result.Name,
		"name_id":       result.NameID,
		"session_index": result.SessionIndex,
		"idp_entity_id": result.IDPEntityID,
		"is_new_user":   result.IsNewUser,
		"attributes":    result.Attributes,
		"expires_at":    result.ExpiresAt,
	})
}

// samlSingleLogoutHandler handles SAML Single Logout (SLO)
func (s *Server) samlSingleLogoutHandler(c *gin.Context) {
	// This is a placeholder for SAML Single Logout functionality
	// In a full implementation, this would handle logout requests from IdP

	var req struct {
		SAMLRequest string `json:"saml_request,omitempty"`
		RelayState  string `json:"relay_state,omitempty"`
	}

	// Try to get from form data first
	if c.Request.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		req.SAMLRequest = c.PostForm("SAMLRequest")
		req.RelayState = c.PostForm("RelayState")
	} else {
		// Try JSON format
		if err := c.ShouldBindJSON(&req); err != nil {
			s.errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request format", gin.H{
				"error": err.Error(),
			})
			return
		}
	}

	// For now, just acknowledge the logout request
	s.successResponse(c, http.StatusOK, gin.H{
		"message":     "Logout request processed",
		"relay_state": req.RelayState,
	})
}

// OpenID Connect handlers

// oidcInitiateHandler initiates OIDC authentication flow
func (s *Server) oidcInitiateHandler(c *gin.Context) {
	provider := c.Param("provider")

	// Validate provider
	if !isValidOIDCProvider(provider) {
		s.errorResponse(c, http.StatusBadRequest, "INVALID_PROVIDER", "Invalid OIDC provider", gin.H{
			"provider":        provider,
			"valid_providers": []string{"oidc"},
		})
		return
	}

	// Get optional nonce from query parameters
	nonce := c.Query("nonce")

	// Generate OIDC authorization URL
	authURL, err := s.ssoService.GetOIDCAuthURL(c.Request.Context(), provider, "", nonce)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"auth_url": authURL,
		"provider": provider,
	})
}

// oidcCallbackHandler handles OIDC callback
func (s *Server) oidcCallbackHandler(c *gin.Context) {
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

	// Validate provider
	if !isValidOIDCProvider(provider) {
		s.errorResponse(c, http.StatusBadRequest, "INVALID_PROVIDER", "Invalid OIDC provider", gin.H{
			"provider": provider,
		})
		return
	}

	// Handle OIDC callback
	result, err := s.ssoService.HandleOIDCCallback(c.Request.Context(), provider, code, state)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	// Return authentication result
	s.successResponse(c, http.StatusOK, gin.H{
		"user_id":       result.UserID,
		"email":         result.Email,
		"name":          result.Name,
		"subject":       result.Subject,
		"provider":      result.Provider,
		"is_new_user":   result.IsNewUser,
		"access_token":  result.AccessToken,
		"refresh_token": result.RefreshToken,
		"id_token":      result.IDToken,
		"expires_at":    result.ExpiresAt,
		"claims":        result.Claims,
	})
}

// oidcValidateTokenHandler validates an OIDC ID token
func (s *Server) oidcValidateTokenHandler(c *gin.Context) {
	var req struct {
		Provider string `json:"provider" binding:"required"`
		IDToken  string `json:"id_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		s.errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request format", gin.H{
			"error": err.Error(),
		})
		return
	}

	// Validate provider
	if !isValidOIDCProvider(req.Provider) {
		s.errorResponse(c, http.StatusBadRequest, "INVALID_PROVIDER", "Invalid OIDC provider", gin.H{
			"provider": req.Provider,
		})
		return
	}

	// Validate ID token
	claims, err := s.ssoService.ValidateOIDCIDToken(c.Request.Context(), req.Provider, req.IDToken)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"valid":      true,
		"claims":     claims,
		"subject":    claims.Subject,
		"email":      claims.Email,
		"expires_at": claims.ExpiresAt,
	})
}

// oidcRefreshTokenHandler refreshes an OIDC access token
func (s *Server) oidcRefreshTokenHandler(c *gin.Context) {
	var req struct {
		Provider     string `json:"provider" binding:"required"`
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		s.errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request format", gin.H{
			"error": err.Error(),
		})
		return
	}

	// Validate provider
	if !isValidOIDCProvider(req.Provider) {
		s.errorResponse(c, http.StatusBadRequest, "INVALID_PROVIDER", "Invalid OIDC provider", gin.H{
			"provider": req.Provider,
		})
		return
	}

	// Refresh token
	tokenResp, err := s.ssoService.RefreshOIDCToken(c.Request.Context(), req.Provider, req.RefreshToken)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"access_token":  tokenResp.AccessToken,
		"refresh_token": tokenResp.RefreshToken,
		"id_token":      tokenResp.IDToken,
		"token_type":    tokenResp.TokenType,
		"expires_in":    tokenResp.ExpiresIn,
		"scope":         tokenResp.Scope,
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

// isValidOIDCProvider checks if the OIDC provider is supported
func isValidOIDCProvider(provider string) bool {
	validProviders := map[string]bool{
		"oidc": true,
	}
	return validProviders[provider]
}
