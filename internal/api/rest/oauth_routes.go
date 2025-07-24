package rest

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/monitoring"
)

// setupOAuthRoutes configures OAuth/SSO routes
func (s *Server) setupOAuthRoutes(group *gin.RouterGroup) {
	// OAuth routes
	oauth := group.Group("/oauth")
	{
		oauth.GET("/:provider/login", s.withMonitoring("oauth_login", s.oauthLoginHandler))
		oauth.GET("/:provider/callback", s.withMonitoring("oauth_callback", s.oauthCallbackHandler))
		oauth.DELETE("/:provider/unlink", s.withMonitoring("oauth_unlink", s.oauthUnlinkHandler))
		oauth.GET("/accounts", s.withMonitoring("oauth_accounts", s.getLinkedAccountsHandler))
	}

	// SAML routes
	saml := group.Group("/saml")
	{
		saml.GET("/metadata", s.withMonitoring("saml_metadata", s.samlMetadataHandler))
		saml.POST("/login", s.withMonitoring("saml_login", s.samlLoginHandler))
		saml.POST("/callback", s.withMonitoring("saml_callback", s.samlCallbackHandler))
	}

	// OIDC routes
	oidc := group.Group("/oidc")
	{
		oidc.GET("/:provider/login", s.withMonitoring("oidc_login", s.oidcLoginHandler))
		oidc.GET("/:provider/callback", s.withMonitoring("oidc_callback", s.oidcCallbackHandler))
		oidc.POST("/:provider/refresh", s.withMonitoring("oidc_refresh", s.oidcRefreshHandler))
	}
}

// OAuth handlers

func (s *Server) oauthLoginHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	provider := c.Param("provider")
	state := c.Query("state")

	if state == "" {
		state = generateRequestID()
	}

	url, err := s.ssoService.GetOAuthURL(ctx, provider, state)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.CategorySystem, "oauth_login", "sso")
			s.trackSecurityEvent(ctx, "oauth_login_failed", "medium", map[string]interface{}{
				"provider": provider,
				"error":    err.Error(),
				"ip":       c.ClientIP(),
			})
		}
		s.handleServiceError(c, err)
		return
	}

	if s.monitoring != nil {
		s.trackSecurityEvent(ctx, "oauth_login_initiated", "low", map[string]interface{}{
			"provider": provider,
			"state":    state,
			"duration": duration.Milliseconds(),
			"ip":       c.ClientIP(),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"url":      url,
		"provider": provider,
		"state":    state,
	})
}

func (s *Server) oauthCallbackHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	provider := c.Param("provider")
	code := c.Query("code")
	state := c.Query("state")

	result, err := s.ssoService.HandleOAuthCallback(ctx, provider, code, state)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.CategorySystem, "oauth_callback", "sso")
			s.trackSecurityEvent(ctx, "oauth_callback_failed", "high", map[string]interface{}{
				"provider": provider,
				"error":    err.Error(),
				"ip":       c.ClientIP(),
			})
		}
		s.handleServiceError(c, err)
		return
	}

	if s.monitoring != nil {
		s.trackAuthEvent(ctx, "oauth_login", result.UserID, true, duration, map[string]interface{}{
			"provider":    provider,
			"email":       result.Email,
			"is_new_user": result.IsNewUser,
		})
		s.trackSecurityEvent(ctx, "oauth_login_success", "low", map[string]interface{}{
			"provider":    provider,
			"user_id":     result.UserID,
			"email":       result.Email,
			"is_new_user": result.IsNewUser,
			"duration":    duration.Milliseconds(),
			"ip":          c.ClientIP(),
		})
	}

	s.successResponse(c, http.StatusOK, result)
}

func (s *Server) oauthUnlinkHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	provider := c.Param("provider")
	userID, _, _, _ := s.getUserContext(c)

	if userID == "" {
		s.unauthorizedResponse(c, "User ID not found in context")
		return
	}

	err := s.ssoService.UnlinkSocialAccount(ctx, userID, provider)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.CategorySystem, "oauth_unlink", "sso")
		}
		s.handleServiceError(c, err)
		return
	}

	if s.monitoring != nil {
		s.trackSecurityEvent(ctx, "oauth_account_unlinked", "medium", map[string]interface{}{
			"provider": provider,
			"user_id":  userID,
			"duration": duration.Milliseconds(),
			"ip":       c.ClientIP(),
		})
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"message": fmt.Sprintf("%s account unlinked successfully", provider),
	})
}

func (s *Server) getLinkedAccountsHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	userID, _, _, _ := s.getUserContext(c)
	if userID == "" {
		s.unauthorizedResponse(c, "User ID not found in context")
		return
	}

	accounts, err := s.ssoService.GetLinkedAccounts(ctx, userID)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.CategorySystem, "get_linked_accounts", "sso")
		}
		s.handleServiceError(c, err)
		return
	}

	if s.monitoring != nil {
		s.trackUserEvent(ctx, "linked_accounts_accessed", userID, map[string]interface{}{
			"account_count": len(accounts),
			"duration":      duration.Milliseconds(),
		})
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"accounts": accounts,
	})
}

// SAML handlers

func (s *Server) samlMetadataHandler(c *gin.Context) {
	ctx := c.Request.Context()

	metadata, err := s.ssoService.GetSAMLMetadata(ctx)
	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.CategorySystem, "saml_metadata", "sso")
		}
		s.handleServiceError(c, err)
		return
	}

	c.Data(http.StatusOK, "application/xml", metadata)
}

func (s *Server) samlLoginHandler(c *gin.Context) {
	ctx := c.Request.Context()

	var req struct {
		IDPEntityID string `json:"idp_entity_id" binding:"required"`
		RelayState  string `json:"relay_state,omitempty"`
	}

	if !s.bindAndValidate(c, &req) {
		return
	}

	result, err := s.ssoService.InitiateSAMLLogin(ctx, req.IDPEntityID, req.RelayState)
	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.CategorySystem, "saml_login", "sso")
		}
		s.handleServiceError(c, err)
		return
	}

	if s.monitoring != nil {
		s.trackSecurityEvent(ctx, "saml_login_initiated", "low", map[string]interface{}{
			"idp_entity_id": req.IDPEntityID,
			"relay_state":   req.RelayState,
			"ip":            c.ClientIP(),
		})
	}

	s.successResponse(c, http.StatusOK, result)
}

func (s *Server) samlCallbackHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	var req struct {
		SAMLResponse string `json:"saml_response" binding:"required"`
		RelayState   string `json:"relay_state,omitempty"`
	}

	if !s.bindAndValidate(c, &req) {
		return
	}

	result, err := s.ssoService.HandleSAMLResponse(ctx, req.SAMLResponse, req.RelayState)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.CategorySystem, "saml_callback", "sso")
			s.trackSecurityEvent(ctx, "saml_callback_failed", "high", map[string]interface{}{
				"error": err.Error(),
				"ip":    c.ClientIP(),
			})
		}
		s.handleServiceError(c, err)
		return
	}

	if s.monitoring != nil {
		s.trackAuthEvent(ctx, "saml_login", result.UserID, true, duration, map[string]interface{}{
			"email":       result.Email,
			"is_new_user": result.IsNewUser,
		})
		s.trackSecurityEvent(ctx, "saml_login_success", "low", map[string]interface{}{
			"user_id":     result.UserID,
			"email":       result.Email,
			"is_new_user": result.IsNewUser,
			"duration":    duration.Milliseconds(),
			"ip":          c.ClientIP(),
		})
	}

	s.successResponse(c, http.StatusOK, result)
}

// OIDC handlers

func (s *Server) oidcLoginHandler(c *gin.Context) {
	ctx := c.Request.Context()

	provider := c.Param("provider")
	state := c.Query("state")
	nonce := c.Query("nonce")

	if state == "" {
		state = generateRequestID()
	}
	if nonce == "" {
		nonce = generateRequestID()
	}

	url, err := s.ssoService.GetOIDCAuthURL(ctx, provider, state, nonce)
	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.CategorySystem, "oidc_login", "sso")
		}
		s.handleServiceError(c, err)
		return
	}

	if s.monitoring != nil {
		s.trackSecurityEvent(ctx, "oidc_login_initiated", "low", map[string]interface{}{
			"provider": provider,
			"state":    state,
			"nonce":    nonce,
			"ip":       c.ClientIP(),
		})
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"url":      url,
		"provider": provider,
		"state":    state,
		"nonce":    nonce,
	})
}

func (s *Server) oidcCallbackHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	provider := c.Param("provider")
	code := c.Query("code")
	state := c.Query("state")

	result, err := s.ssoService.HandleOIDCCallback(ctx, provider, code, state)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.CategorySystem, "oidc_callback", "sso")
			s.trackSecurityEvent(ctx, "oidc_callback_failed", "high", map[string]interface{}{
				"provider": provider,
				"error":    err.Error(),
				"ip":       c.ClientIP(),
			})
		}
		s.handleServiceError(c, err)
		return
	}

	if s.monitoring != nil {
		s.trackAuthEvent(ctx, "oidc_login", result.UserID, true, duration, map[string]interface{}{
			"provider":    provider,
			"email":       result.Email,
			"is_new_user": result.IsNewUser,
		})
		s.trackSecurityEvent(ctx, "oidc_login_success", "low", map[string]interface{}{
			"provider":    provider,
			"user_id":     result.UserID,
			"email":       result.Email,
			"is_new_user": result.IsNewUser,
			"duration":    duration.Milliseconds(),
			"ip":          c.ClientIP(),
		})
	}

	s.successResponse(c, http.StatusOK, result)
}

func (s *Server) oidcRefreshHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	provider := c.Param("provider")

	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if !s.bindAndValidate(c, &req) {
		return
	}

	result, err := s.ssoService.RefreshOIDCToken(ctx, provider, req.RefreshToken)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.CategorySystem, "oidc_refresh", "sso")
		}
		s.handleServiceError(c, err)
		return
	}

	if s.monitoring != nil {
		s.monitoring.RecordTokenEvent(ctx, "refresh", "oidc_token", true, map[string]interface{}{
			"provider": provider,
			"duration": duration.Milliseconds(),
		})
	}

	s.successResponse(c, http.StatusOK, result)
}
