package rest

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/service/email"
)

// EmailRoutes handles email-related HTTP endpoints
type EmailRoutes struct {
	emailService email.EmailService
}

// NewEmailRoutes creates a new EmailRoutes instance
func NewEmailRoutes(emailService email.EmailService) *EmailRoutes {
	return &EmailRoutes{
		emailService: emailService,
	}
}

// RegisterRoutes registers email routes with the router
func (r *EmailRoutes) RegisterRoutes(router *gin.RouterGroup) {
	emailGroup := router.Group("/email")
	{
		// Email sending endpoints
		emailGroup.POST("/send", r.SendEmail)
		emailGroup.POST("/send/bulk", r.SendBulkEmails)

		// Pre-made template endpoints
		emailGroup.POST("/send/welcome", r.SendWelcomeEmail)
		emailGroup.POST("/send/verification", r.SendVerificationEmail)
		emailGroup.POST("/send/password-reset", r.SendPasswordResetEmail)
		emailGroup.POST("/send/login-notification", r.SendLoginNotificationEmail)
		emailGroup.POST("/send/mfa-code", r.SendMFACodeEmail)
		emailGroup.POST("/send/account-locked", r.SendAccountLockedEmail)
		emailGroup.POST("/send/password-changed", r.SendPasswordChangedEmail)

		// Template management endpoints
		templateGroup := emailGroup.Group("/templates")
		{
			templateGroup.POST("", r.CreateTemplate)
			templateGroup.GET("", r.ListTemplates)
			templateGroup.GET("/:id", r.GetTemplate)
			templateGroup.PUT("/:id", r.UpdateTemplate)
			templateGroup.DELETE("/:id", r.DeleteTemplate)
		}

		// Analytics endpoints
		analyticsGroup := emailGroup.Group("/analytics")
		{
			analyticsGroup.GET("/status/:emailId", r.GetEmailStatus)
			analyticsGroup.GET("/reports", r.GetEmailAnalytics)
		}

		// Health check
		emailGroup.GET("/health", r.HealthCheck)
	}
}

// SendEmail sends a custom email
func (r *EmailRoutes) SendEmail(c *gin.Context) {
	var req email.SendEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	if err := r.emailService.SendEmail(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send email", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Email sent successfully"})
}

// SendBulkEmails sends multiple emails
func (r *EmailRoutes) SendBulkEmails(c *gin.Context) {
	var req email.BulkEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	if err := r.emailService.SendBulkEmails(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send bulk emails", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Bulk emails sent successfully"})
}

// Pre-made template endpoints

type WelcomeEmailRequest struct {
	To   string `json:"to" binding:"required,email"`
	Name string `json:"name" binding:"required"`
}

func (r *EmailRoutes) SendWelcomeEmail(c *gin.Context) {
	var req WelcomeEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	if err := r.emailService.SendWelcomeEmail(c.Request.Context(), req.To, req.Name); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send welcome email", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Welcome email sent successfully"})
}

type VerificationEmailRequest struct {
	To    string `json:"to" binding:"required,email"`
	Name  string `json:"name" binding:"required"`
	Token string `json:"token" binding:"required"`
}

func (r *EmailRoutes) SendVerificationEmail(c *gin.Context) {
	var req VerificationEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	if err := r.emailService.SendVerificationEmail(c.Request.Context(), req.To, req.Name, req.Token); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send verification email", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Verification email sent successfully"})
}

type PasswordResetEmailRequest struct {
	To    string `json:"to" binding:"required,email"`
	Name  string `json:"name" binding:"required"`
	Token string `json:"token" binding:"required"`
}

func (r *EmailRoutes) SendPasswordResetEmail(c *gin.Context) {
	var req PasswordResetEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	if err := r.emailService.SendPasswordResetEmail(c.Request.Context(), req.To, req.Name, req.Token); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send password reset email", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password reset email sent successfully"})
}

type LoginNotificationEmailRequest struct {
	To       string `json:"to" binding:"required,email"`
	Name     string `json:"name" binding:"required"`
	Location string `json:"location" binding:"required"`
	Device   string `json:"device" binding:"required"`
}

func (r *EmailRoutes) SendLoginNotificationEmail(c *gin.Context) {
	var req LoginNotificationEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	if err := r.emailService.SendLoginNotificationEmail(c.Request.Context(), req.To, req.Name, req.Location, req.Device); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send login notification email", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Login notification email sent successfully"})
}

type MFACodeEmailRequest struct {
	To   string `json:"to" binding:"required,email"`
	Name string `json:"name" binding:"required"`
	Code string `json:"code" binding:"required"`
}

func (r *EmailRoutes) SendMFACodeEmail(c *gin.Context) {
	var req MFACodeEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	if err := r.emailService.SendMFACodeEmail(c.Request.Context(), req.To, req.Name, req.Code); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send MFA code email", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "MFA code email sent successfully"})
}

type AccountLockedEmailRequest struct {
	To   string `json:"to" binding:"required,email"`
	Name string `json:"name" binding:"required"`
}

func (r *EmailRoutes) SendAccountLockedEmail(c *gin.Context) {
	var req AccountLockedEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	if err := r.emailService.SendAccountLockedEmail(c.Request.Context(), req.To, req.Name); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send account locked email", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Account locked email sent successfully"})
}

type PasswordChangedEmailRequest struct {
	To   string `json:"to" binding:"required,email"`
	Name string `json:"name" binding:"required"`
}

func (r *EmailRoutes) SendPasswordChangedEmail(c *gin.Context) {
	var req PasswordChangedEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	if err := r.emailService.SendPasswordChangedEmail(c.Request.Context(), req.To, req.Name); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send password changed email", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password changed email sent successfully"})
}

// Template management endpoints

func (r *EmailRoutes) CreateTemplate(c *gin.Context) {
	var template email.EmailTemplate
	if err := c.ShouldBindJSON(&template); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	if err := r.emailService.CreateTemplate(c.Request.Context(), &template); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create template", "details": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Template created successfully", "template": template})
}

func (r *EmailRoutes) ListTemplates(c *gin.Context) {
	filter := &email.TemplateFilter{}

	// Parse query parameters
	if category := c.Query("category"); category != "" {
		filter.Category = category
	}

	if search := c.Query("search"); search != "" {
		filter.Search = search
	}

	if isActiveStr := c.Query("is_active"); isActiveStr != "" {
		if isActive, err := strconv.ParseBool(isActiveStr); err == nil {
			filter.IsActive = &isActive
		}
	}

	if limitStr := c.Query("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 {
			filter.Limit = limit
		}
	}

	if offsetStr := c.Query("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			filter.Offset = offset
		}
	}

	templates, err := r.emailService.ListTemplates(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list templates", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"templates": templates})
}

func (r *EmailRoutes) GetTemplate(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Template ID is required"})
		return
	}

	template, err := r.emailService.GetTemplate(c.Request.Context(), id)
	if err != nil {
		if err == email.ErrTemplateNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Template not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get template", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"template": template})
}

func (r *EmailRoutes) UpdateTemplate(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Template ID is required"})
		return
	}

	var template email.EmailTemplate
	if err := c.ShouldBindJSON(&template); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	if err := r.emailService.UpdateTemplate(c.Request.Context(), id, &template); err != nil {
		if err == email.ErrTemplateNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Template not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update template", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Template updated successfully", "template": template})
}

func (r *EmailRoutes) DeleteTemplate(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Template ID is required"})
		return
	}

	if err := r.emailService.DeleteTemplate(c.Request.Context(), id); err != nil {
		if err == email.ErrTemplateNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Template not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete template", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Template deleted successfully"})
}

// Analytics endpoints

func (r *EmailRoutes) GetEmailStatus(c *gin.Context) {
	emailID := c.Param("emailId")
	if emailID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email ID is required"})
		return
	}

	status, err := r.emailService.GetEmailStatus(c.Request.Context(), emailID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get email status", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": status})
}

func (r *EmailRoutes) GetEmailAnalytics(c *gin.Context) {
	filter := &email.AnalyticsFilter{}

	// Parse query parameters
	if fromStr := c.Query("from"); fromStr != "" {
		if from, err := parseTimeParam(fromStr); err == nil {
			filter.From = from
		}
	}

	if toStr := c.Query("to"); toStr != "" {
		if to, err := parseTimeParam(toStr); err == nil {
			filter.To = to
		}
	}

	if templateID := c.Query("template_id"); templateID != "" {
		filter.TemplateID = templateID
	}

	if category := c.Query("category"); category != "" {
		filter.Category = category
	}

	analytics, err := r.emailService.GetEmailAnalytics(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get email analytics", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"analytics": analytics})
}

// HealthCheck checks the health of the email service
func (r *EmailRoutes) HealthCheck(c *gin.Context) {
	if err := r.emailService.HealthCheck(c.Request.Context()); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Email service is unhealthy", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "healthy", "message": "Email service is operational"})
}

// parseTimeParam parses a time parameter from query string
func parseTimeParam(timeStr string) (time.Time, error) {
	// Try different time formats
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, timeStr); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("invalid time format: %s", timeStr)
}
