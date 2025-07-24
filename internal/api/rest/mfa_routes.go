package rest

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/service/mfa"
)

// setupMFARoutes configures MFA routes
func (s *Server) setupMFARoutes(group *gin.RouterGroup) {
	mfaGroup := group.Group("/mfa")
	{
		// TOTP endpoints
		totpGroup := mfaGroup.Group("/totp")
		{
			totpGroup.POST("/setup", s.setupTOTPHandler)
			totpGroup.POST("/verify", s.verifyTOTPHandler)
		}

		// SMS endpoints
		smsGroup := mfaGroup.Group("/sms")
		{
			smsGroup.POST("/setup", s.setupSMSHandler)
			smsGroup.POST("/send-code", s.sendSMSCodeHandler)
			smsGroup.POST("/verify", s.verifySMSHandler)
		}

		// Email endpoints
		emailGroup := mfaGroup.Group("/email")
		{
			emailGroup.POST("/setup", s.setupEmailHandler)
			emailGroup.POST("/send-code", s.sendEmailCodeHandler)
			emailGroup.POST("/verify", s.verifyEmailHandler)
		}

		// WebAuthn endpoints
		webauthnGroup := mfaGroup.Group("/webauthn")
		{
			webauthnGroup.POST("/setup", s.setupWebAuthnHandler)
			webauthnGroup.POST("/setup/finish", s.finishWebAuthnSetupHandler)
			webauthnGroup.POST("/login/begin", s.beginWebAuthnLoginHandler)
			webauthnGroup.POST("/login/finish", s.finishWebAuthnLoginHandler)
		}

		// Backup codes endpoints
		backupGroup := mfaGroup.Group("/backup-codes")
		{
			backupGroup.POST("/generate", s.generateBackupCodesHandler)
			backupGroup.POST("/verify", s.verifyBackupCodeHandler)
		}

		// General MFA endpoints
		mfaGroup.GET("/methods/:userID", s.getUserMFAMethodsHandler)
		mfaGroup.POST("/disable", s.disableMFAHandler)
		mfaGroup.POST("/validate-login", s.validateMFAForLoginHandler)
	}
}

// TOTP handlers

// setupTOTPHandler sets up TOTP-based MFA for a user
func (s *Server) setupTOTPHandler(c *gin.Context) {
	var req mfa.SetupTOTPRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	response, err := s.mfaService.SetupTOTP(c.Request.Context(), &req)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, response)
}

// verifyTOTPHandler verifies a TOTP code for authentication
func (s *Server) verifyTOTPHandler(c *gin.Context) {
	var req mfa.VerifyTOTPRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	response, err := s.mfaService.VerifyTOTP(c.Request.Context(), &req)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	if !response.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid TOTP code", "message": response.Message})
		return
	}

	s.successResponse(c, http.StatusOK, response)
}

// SMS handlers

// setupSMSHandler sets up SMS-based MFA for a user
func (s *Server) setupSMSHandler(c *gin.Context) {
	var req mfa.SetupSMSRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	response, err := s.mfaService.SetupSMS(c.Request.Context(), &req)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, response)
}

// sendSMSCodeHandler sends an SMS verification code
func (s *Server) sendSMSCodeHandler(c *gin.Context) {
	var req mfa.SendSMSCodeRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	response, err := s.mfaService.SendSMSCode(c.Request.Context(), &req)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, response)
}

// verifySMSHandler verifies an SMS code for authentication
func (s *Server) verifySMSHandler(c *gin.Context) {
	var req mfa.VerifySMSRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	response, err := s.mfaService.VerifySMS(c.Request.Context(), &req)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	if !response.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid SMS code", "message": response.Message})
		return
	}

	s.successResponse(c, http.StatusOK, response)
}

// Email handlers

// setupEmailHandler sets up email-based MFA for a user
func (s *Server) setupEmailHandler(c *gin.Context) {
	var req mfa.SetupEmailRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	response, err := s.mfaService.SetupEmail(c.Request.Context(), &req)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, response)
}

// sendEmailCodeHandler sends an email verification code
func (s *Server) sendEmailCodeHandler(c *gin.Context) {
	var req mfa.SendEmailCodeRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	response, err := s.mfaService.SendEmailCode(c.Request.Context(), &req)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, response)
}

// verifyEmailHandler verifies an email code for authentication
func (s *Server) verifyEmailHandler(c *gin.Context) {
	var req mfa.VerifyEmailRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	response, err := s.mfaService.VerifyEmail(c.Request.Context(), &req)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	if !response.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email code", "message": response.Message})
		return
	}

	s.successResponse(c, http.StatusOK, response)
}

// WebAuthn handlers

// setupWebAuthnHandler initiates WebAuthn credential registration
func (s *Server) setupWebAuthnHandler(c *gin.Context) {
	var req mfa.SetupWebAuthnRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	response, err := s.mfaService.SetupWebAuthn(c.Request.Context(), &req)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, response)
}

// finishWebAuthnSetupHandler completes WebAuthn credential registration
func (s *Server) finishWebAuthnSetupHandler(c *gin.Context) {
	var req mfa.FinishWebAuthnSetupRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	response, err := s.mfaService.FinishWebAuthnSetup(c.Request.Context(), &req)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	if !response.Success {
		c.JSON(http.StatusBadRequest, gin.H{"error": "WebAuthn setup failed", "message": response.Message})
		return
	}

	s.successResponse(c, http.StatusOK, response)
}

// beginWebAuthnLoginHandler initiates WebAuthn authentication
func (s *Server) beginWebAuthnLoginHandler(c *gin.Context) {
	var req mfa.BeginWebAuthnLoginRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	response, err := s.mfaService.BeginWebAuthnLogin(c.Request.Context(), &req)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, response)
}

// finishWebAuthnLoginHandler completes WebAuthn authentication
func (s *Server) finishWebAuthnLoginHandler(c *gin.Context) {
	var req mfa.FinishWebAuthnLoginRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	response, err := s.mfaService.FinishWebAuthnLogin(c.Request.Context(), &req)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	if !response.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "WebAuthn authentication failed", "message": response.Message})
		return
	}

	s.successResponse(c, http.StatusOK, response)
}

// Backup codes handlers

// generateBackupCodesHandler generates backup codes for MFA recovery
func (s *Server) generateBackupCodesHandler(c *gin.Context) {
	var req mfa.GenerateBackupCodesRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	response, err := s.mfaService.GenerateBackupCodes(c.Request.Context(), &req)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, response)
}

// verifyBackupCodeHandler verifies a backup code for MFA recovery
func (s *Server) verifyBackupCodeHandler(c *gin.Context) {
	var req mfa.VerifyBackupCodeRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	response, err := s.mfaService.VerifyBackupCode(c.Request.Context(), &req)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	if !response.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid backup code", "message": response.Message})
		return
	}

	s.successResponse(c, http.StatusOK, response)
}

// General MFA handlers

// getUserMFAMethodsHandler retrieves all MFA methods for a user
func (s *Server) getUserMFAMethodsHandler(c *gin.Context) {
	userID := c.Param("userID")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	response, err := s.mfaService.GetUserMFAMethods(c.Request.Context(), userID)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, response)
}

// disableMFAHandler disables a specific MFA method for a user
func (s *Server) disableMFAHandler(c *gin.Context) {
	var req mfa.DisableMFARequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	err := s.mfaService.DisableMFA(c.Request.Context(), &req)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, gin.H{"message": "MFA method disabled successfully"})
}

// validateMFAForLoginHandler validates MFA during login process
func (s *Server) validateMFAForLoginHandler(c *gin.Context) {
	var req mfa.ValidateMFAForLoginRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	response, err := s.mfaService.ValidateMFAForLogin(c.Request.Context(), &req)
	if err != nil {
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, response)
}
