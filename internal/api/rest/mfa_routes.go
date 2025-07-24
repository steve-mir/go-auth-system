package rest

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/monitoring"
	"github.com/steve-mir/go-auth-system/internal/service/mfa"
)

// setupMFARoutes configures MFA routes
func (s *Server) setupMFARoutes(group *gin.RouterGroup) {
	mfaGroup := group.Group("/mfa")
	{
		// TOTP routes
		mfaGroup.POST("/totp/setup", s.withMonitoring("mfa_totp_setup", s.setupTOTPHandler))
		mfaGroup.POST("/totp/verify", s.withMonitoring("mfa_totp_verify", s.verifyTOTPHandler))
		mfaGroup.POST("/totp/disable", s.withMonitoring("mfa_totp_disable", s.disableTOTPHandler))

		// SMS routes
		mfaGroup.POST("/sms/setup", s.withMonitoring("mfa_sms_setup", s.setupSMSHandler))
		mfaGroup.POST("/sms/send", s.withMonitoring("mfa_sms_send", s.sendSMSCodeHandler))
		mfaGroup.POST("/sms/verify", s.withMonitoring("mfa_sms_verify", s.verifySMSHandler))
		mfaGroup.POST("/sms/disable", s.withMonitoring("mfa_sms_disable", s.disableSMSHandler))

		// Email routes
		mfaGroup.POST("/email/setup", s.withMonitoring("mfa_email_setup", s.setupEmailHandler))
		mfaGroup.POST("/email/send", s.withMonitoring("mfa_email_send", s.sendEmailCodeHandler))
		mfaGroup.POST("/email/verify", s.withMonitoring("mfa_email_verify", s.verifyEmailHandler))
		mfaGroup.POST("/email/disable", s.withMonitoring("mfa_email_disable", s.disableEmailHandler))

		// WebAuthn routes
		mfaGroup.POST("/webauthn/register/begin", s.withMonitoring("mfa_webauthn_register_begin", s.beginWebAuthnRegistrationHandler))
		mfaGroup.POST("/webauthn/register/finish", s.withMonitoring("mfa_webauthn_register_finish", s.finishWebAuthnRegistrationHandler))
		mfaGroup.POST("/webauthn/login/begin", s.withMonitoring("mfa_webauthn_login_begin", s.beginWebAuthnLoginHandler))
		mfaGroup.POST("/webauthn/login/finish", s.withMonitoring("mfa_webauthn_login_finish", s.finishWebAuthnLoginHandler))
		mfaGroup.DELETE("/webauthn/credentials/:credential_id", s.withMonitoring("mfa_webauthn_delete", s.deleteWebAuthnCredentialHandler))

		// Backup codes routes
		mfaGroup.POST("/backup-codes/generate", s.withMonitoring("mfa_backup_codes_generate", s.generateBackupCodesHandler))
		mfaGroup.POST("/backup-codes/verify", s.withMonitoring("mfa_backup_codes_verify", s.verifyBackupCodeHandler))

		// MFA status and management
		mfaGroup.GET("/status", s.withMonitoring("mfa_status", s.getMFAStatusHandler))
		mfaGroup.GET("/methods", s.withMonitoring("mfa_methods", s.getMFAMethodsHandler))
		mfaGroup.POST("/disable-all", s.withMonitoring("mfa_disable_all", s.disableAllMFAHandler))
	}
}

// TOTP handlers

func (s *Server) setupTOTPHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	userID, _, _, _ := s.getUserContext(c)
	if userID == "" {
		s.unauthorizedResponse(c, "User ID not found in context")
		return
	}
	req := mfa.SetupTOTPRequest{
		UserID: userID,
		// AccountName: "",
		// Issuer: "",
	}

	result, err := s.mfaService.SetupTOTP(ctx, &req)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.CategorySystem, "setup_totp", "mfa")
			s.monitoring.RecordMFAFailure("totp", "setup_failed")
		}
		s.handleServiceError(c, err)
		return
	}

	if s.monitoring != nil {
		s.monitoring.RecordMFAAttempt("totp")
		s.trackSecurityEvent(ctx, "mfa_totp_setup", "medium", map[string]interface{}{
			"user_id":  userID,
			"duration": duration.Milliseconds(),
			"ip":       c.ClientIP(),
		})
	}

	s.successResponse(c, http.StatusOK, result)
}

func (s *Server) verifyTOTPHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	userID, _, _, _ := s.getUserContext(c)
	if userID == "" {
		s.unauthorizedResponse(c, "User ID not found in context")
		return
	}

	var req mfa.VerifyTOTPRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	req.UserID = userID

	result, err := s.mfaService.VerifyTOTP(ctx, &req)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.CategorySystem, "verify_totp", "mfa")
			s.monitoring.RecordMFAFailure("totp", "verification_failed")
			s.trackSecurityEvent(ctx, "mfa_totp_failed", "high", map[string]interface{}{
				"user_id": userID,
				"error":   err.Error(),
				"ip":      c.ClientIP(),
			})
		}
		s.handleServiceError(c, err)
		return
	}

	if s.monitoring != nil {
		if result.Valid {
			s.monitoring.RecordMFASuccess("totp")
			s.trackSecurityEvent(ctx, "mfa_totp_success", "low", map[string]interface{}{
				"user_id":  userID,
				"duration": duration.Milliseconds(),
				"ip":       c.ClientIP(),
			})
		} else {
			s.monitoring.RecordMFAFailure("totp", "invalid_code")
			s.trackSecurityEvent(ctx, "mfa_totp_invalid", "medium", map[string]interface{}{
				"user_id": userID,
				"ip":      c.ClientIP(),
			})
		}
	}

	s.successResponse(c, http.StatusOK, result)
}

func (s *Server) disableTOTPHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	userID, _, _, _ := s.getUserContext(c)
	if userID == "" {
		s.unauthorizedResponse(c, "User ID not found in context")
		return
	}

	req := mfa.DisableMFARequest{
		UserID: userID,
		Method: mfa.MethodTOTP,
	}
	err := s.mfaService.DisableMFA(ctx, &req)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.CategorySystem, "disable_totp", "mfa")
		}
		s.handleServiceError(c, err)
		return
	}

	if s.monitoring != nil {
		s.trackSecurityEvent(ctx, "mfa_totp_disabled", "high", map[string]interface{}{
			"user_id":  userID,
			"duration": duration.Milliseconds(),
			"ip":       c.ClientIP(),
		})
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"message": "TOTP disabled successfully",
	})
}

// SMS handlers

func (s *Server) setupSMSHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	userID, _, _, _ := s.getUserContext(c)
	if userID == "" {
		s.unauthorizedResponse(c, "User ID not found in context")
		return
	}

	var req mfa.SetupSMSRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	req.UserID = userID

	_, err := s.mfaService.SetupSMS(ctx, &req)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.CategorySystem, "setup_sms", "mfa")
			s.monitoring.RecordMFAFailure("sms", "setup_failed")
		}
		s.handleServiceError(c, err)
		return
	}

	if s.monitoring != nil {
		s.monitoring.RecordMFAAttempt("sms")
		s.trackSecurityEvent(ctx, "mfa_sms_setup", "medium", map[string]interface{}{
			"user_id":      userID,
			"phone_number": req.PhoneNumber,
			"duration":     duration.Milliseconds(),
			"ip":           c.ClientIP(),
		})
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"message": "SMS MFA setup successfully",
	})
}

func (s *Server) sendSMSCodeHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	userID, _, _, _ := s.getUserContext(c)
	if userID == "" {
		s.unauthorizedResponse(c, "User ID not found in context")
		return
	}

	req := mfa.SendSMSCodeRequest{
		UserID:   userID,
		ForLogin: true,
	}
	_, err := s.mfaService.SendSMSCode(ctx, &req)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.CategorySystem, "send_sms_code", "mfa")
		}
		s.handleServiceError(c, err)
		return
	}

	if s.monitoring != nil {
		s.trackSecurityEvent(ctx, "mfa_sms_code_sent", "low", map[string]interface{}{
			"user_id":  userID,
			"duration": duration.Milliseconds(),
			"ip":       c.ClientIP(),
		})
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"message": "SMS code sent successfully",
	})
}

func (s *Server) verifySMSHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	userID, _, _, _ := s.getUserContext(c)
	if userID == "" {
		s.unauthorizedResponse(c, "User ID not found in context")
		return
	}

	var req mfa.VerifySMSRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	req.UserID = userID

	result, err := s.mfaService.VerifySMS(ctx, &req)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.CategorySystem, "verify_sms", "mfa")
			s.monitoring.RecordMFAFailure("sms", "verification_failed")
		}
		s.handleServiceError(c, err)
		return
	}

	if s.monitoring != nil {
		if result.Valid {
			s.monitoring.RecordMFASuccess("sms")
			s.trackSecurityEvent(ctx, "mfa_sms_success", "low", map[string]interface{}{
				"user_id":  userID,
				"duration": duration.Milliseconds(),
				"ip":       c.ClientIP(),
			})
		} else {
			s.monitoring.RecordMFAFailure("sms", "invalid_code")
			s.trackSecurityEvent(ctx, "mfa_sms_invalid", "medium", map[string]interface{}{
				"user_id": userID,
				"ip":      c.ClientIP(),
			})
		}
	}

	s.successResponse(c, http.StatusOK, result)
}

func (s *Server) disableSMSHandler(c *gin.Context) {
	ctx := c.Request.Context()

	userID, _, _, _ := s.getUserContext(c)
	if userID == "" {
		s.unauthorizedResponse(c, "User ID not found in context")
		return
	}

	req := mfa.DisableMFARequest{
		UserID: userID,
		Method: mfa.MethodSMS,
	}
	err := s.mfaService.DisableMFA(ctx, &req)
	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.CategorySystem, "disable_sms", "mfa")
		}
		s.handleServiceError(c, err)
		return
	}

	if s.monitoring != nil {
		s.trackSecurityEvent(ctx, "mfa_sms_disabled", "high", map[string]interface{}{
			"user_id": userID,
			"ip":      c.ClientIP(),
		})
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"message": "SMS MFA disabled successfully",
	})
}

// Email handlers (similar pattern to SMS)

func (s *Server) setupEmailHandler(c *gin.Context) {
	// Implementation similar to setupSMSHandler
	s.successResponse(c, http.StatusNotImplemented, gin.H{
		"message": "Email MFA setup not implemented yet",
	})
}

func (s *Server) sendEmailCodeHandler(c *gin.Context) {
	// Implementation similar to sendSMSCodeHandler
	s.successResponse(c, http.StatusNotImplemented, gin.H{
		"message": "Email code sending not implemented yet",
	})
}

func (s *Server) verifyEmailHandler(c *gin.Context) {
	// Implementation similar to verifySMSHandler
	s.successResponse(c, http.StatusNotImplemented, gin.H{
		"message": "Email MFA verification not implemented yet",
	})
}

func (s *Server) disableEmailHandler(c *gin.Context) {
	// Implementation similar to disableSMSHandler
	s.successResponse(c, http.StatusNotImplemented, gin.H{
		"message": "Email MFA disable not implemented yet",
	})
}

// WebAuthn handlers

func (s *Server) beginWebAuthnRegistrationHandler(c *gin.Context) {
	ctx := c.Request.Context()

	userID, _, _, _ := s.getUserContext(c)
	if userID == "" {
		s.unauthorizedResponse(c, "User ID not found in context")
		return
	}

	req := mfa.SetupWebAuthnRequest{
		UserID: userID,
	}
	result, err := s.mfaService.SetupWebAuthn(ctx, &req)
	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.CategorySystem, "begin_webauthn_registration", "mfa")
		}
		s.handleServiceError(c, err)
		return
	}

	if s.monitoring != nil {
		s.trackSecurityEvent(ctx, "webauthn_registration_begin", "low", map[string]interface{}{
			"user_id": userID,
			"ip":      c.ClientIP(),
		})
	}

	s.successResponse(c, http.StatusOK, result)
}

func (s *Server) finishWebAuthnRegistrationHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	userID, _, _, _ := s.getUserContext(c)
	if userID == "" {
		s.unauthorizedResponse(c, "User ID not found in context")
		return
	}

	var req mfa.FinishWebAuthnSetupRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	req.UserID = userID

	result, err := s.mfaService.FinishWebAuthnSetup(ctx, &req)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.CategorySystem, "finish_webauthn_registration", "mfa")
			s.monitoring.RecordMFAFailure("webauthn", "registration_failed")
		}
		s.handleServiceError(c, err)
		return
	}

	if s.monitoring != nil {
		s.monitoring.RecordMFASuccess("webauthn")
		s.trackSecurityEvent(ctx, "webauthn_registered", "medium", map[string]interface{}{
			"user_id":       userID,
			"credential_id": result.CredentialID,
			"duration":      duration.Milliseconds(),
			"ip":            c.ClientIP(),
		})
	}

	s.successResponse(c, http.StatusOK, result)
}

func (s *Server) beginWebAuthnLoginHandler(c *gin.Context) {
	// Implementation for WebAuthn login begin
	s.successResponse(c, http.StatusNotImplemented, gin.H{
		"message": "WebAuthn login begin not implemented yet",
	})
}

func (s *Server) finishWebAuthnLoginHandler(c *gin.Context) {
	// Implementation for WebAuthn login finish
	s.successResponse(c, http.StatusNotImplemented, gin.H{
		"message": "WebAuthn login finish not implemented yet",
	})
}

func (s *Server) deleteWebAuthnCredentialHandler(c *gin.Context) {
	ctx := c.Request.Context()

	userID, _, _, _ := s.getUserContext(c)
	if userID == "" {
		s.unauthorizedResponse(c, "User ID not found in context")
		return
	}

	credentialID := c.Param("credential_id")
	if credentialID == "" {
		s.badRequestResponse(c, "Missing credential ID", nil)
		return
	}

	req := mfa.DisableMFARequest{
		UserID:   userID,
		ConfigID: credentialID,
		Method:   mfa.MethodWebAuthn,
	}
	err := s.mfaService.DisableMFA(ctx, &req)
	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.CategorySystem, "delete_webauthn_credential", "mfa")
		}
		s.handleServiceError(c, err)
		return
	}

	if s.monitoring != nil {
		s.trackSecurityEvent(ctx, "webauthn_credential_deleted", "high", map[string]interface{}{
			"user_id":       userID,
			"credential_id": credentialID,
			"ip":            c.ClientIP(),
		})
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"message": "WebAuthn credential deleted successfully",
	})
}

// Backup codes handlers

func (s *Server) generateBackupCodesHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	userID, _, _, _ := s.getUserContext(c)
	if userID == "" {
		s.unauthorizedResponse(c, "User ID not found in context")
		return
	}
	req := mfa.GenerateBackupCodesRequest{
		UserID: userID,
		// ConfigID: "", TODO:
	}

	codes, err := s.mfaService.GenerateBackupCodes(ctx, &req)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.CategorySystem, "generate_backup_codes", "mfa")
		}
		s.handleServiceError(c, err)
		return
	}

	if s.monitoring != nil {
		s.trackSecurityEvent(ctx, "backup_codes_generated", "high", map[string]interface{}{
			"user_id":    userID,
			"code_count": len(codes.BackupCodes),
			"duration":   duration.Milliseconds(),
			"ip":         c.ClientIP(),
		})
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"backup_codes": codes,
		"message":      "Backup codes generated successfully. Store them securely.",
	})
}

func (s *Server) verifyBackupCodeHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	userID, _, _, _ := s.getUserContext(c)
	if userID == "" {
		s.unauthorizedResponse(c, "User ID not found in context")
		return
	}

	var req mfa.VerifyBackupCodeRequest
	if !s.bindAndValidate(c, &req) {
		return
	}

	req.UserID = userID

	result, err := s.mfaService.VerifyBackupCode(ctx, &req)
	duration := time.Since(start)

	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.CategorySystem, "verify_backup_code", "mfa")
			s.monitoring.RecordMFAFailure("backup_code", "verification_failed")
		}
		s.handleServiceError(c, err)
		return
	}

	if s.monitoring != nil {
		if result.Valid {
			s.monitoring.RecordMFASuccess("backup_code")
			s.trackSecurityEvent(ctx, "backup_code_used", "high", map[string]interface{}{
				"user_id":  userID,
				"duration": duration.Milliseconds(),
				"ip":       c.ClientIP(),
			})
		} else {
			s.monitoring.RecordMFAFailure("backup_code", "invalid_code")
			s.trackSecurityEvent(ctx, "backup_code_invalid", "medium", map[string]interface{}{
				"user_id": userID,
				"ip":      c.ClientIP(),
			})
		}
	}

	s.successResponse(c, http.StatusOK, result)
}

// MFA status and management handlers

func (s *Server) getMFAStatusHandler(c *gin.Context) {
	ctx := c.Request.Context()

	userID, _, _, _ := s.getUserContext(c)
	if userID == "" {
		s.unauthorizedResponse(c, "User ID not found in context")
		return
	}

	req := mfa.ValidateMFAForLoginRequest{
		UserID: userID,
	}
	status, err := s.mfaService.ValidateMFAForLogin(ctx, &req)
	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.CategorySystem, "get_mfa_status", "mfa")
		}
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, status)
}

func (s *Server) getMFAMethodsHandler(c *gin.Context) {
	ctx := c.Request.Context()

	userID, _, _, _ := s.getUserContext(c)
	if userID == "" {
		s.unauthorizedResponse(c, "User ID not found in context")
		return
	}

	methods, err := s.mfaService.GetUserMFAMethods(ctx, userID)
	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.CategorySystem, "get_mfa_methods", "mfa")
		}
		s.handleServiceError(c, err)
		return
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"methods": methods,
	})
}

func (s *Server) disableAllMFAHandler(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	userID, _, _, _ := s.getUserContext(c)
	if userID == "" {
		s.unauthorizedResponse(c, "User ID not found in context")
		return
	}

	// Get all user MFA methods first
	methods, err := s.mfaService.GetUserMFAMethods(ctx, userID)
	if err != nil {
		if s.monitoring != nil {
			s.trackError(ctx, err, monitoring.CategorySystem, "disable_all_mfa", "mfa")
		}
		s.handleServiceError(c, err)
		return
	}

	// Disable each MFA method
	for _, method := range methods.Methods {
		req := mfa.DisableMFARequest{
			UserID:   userID,
			ConfigID: method.ID.String(),
			Method:   method.Method,
		}
		if err := s.mfaService.DisableMFA(ctx, &req); err != nil {
			if s.monitoring != nil {
				s.trackError(ctx, err, monitoring.CategorySystem, "disable_all_mfa", "mfa")
			}
			// Continue with other methods even if one fails
		}
	}

	duration := time.Since(start)

	if s.monitoring != nil {
		s.trackSecurityEvent(ctx, "all_mfa_disabled", "critical", map[string]interface{}{
			"user_id":  userID,
			"duration": duration.Milliseconds(),
			"ip":       c.ClientIP(),
		})
	}

	s.successResponse(c, http.StatusOK, gin.H{
		"message": "All MFA methods disabled successfully",
	})
}
