package email

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/steve-mir/go-auth-system/internal/errors"
	"github.com/steve-mir/go-auth-system/internal/interfaces"
)

// Email service specific errors
var (
	ErrTemplateNotFound = errors.New(
		errors.ErrorTypeNotFound,
		"TEMPLATE_NOT_FOUND",
		"Email template not found",
	)
)

// Service implements the EmailService interface
type Service struct {
	config    *EmailConfig
	providers map[string]Provider
	templates TemplateRepository
	queue     QueueRepository
	analytics AnalyticsRepository
	logger    *slog.Logger
	mu        sync.RWMutex
}

// NewService creates a new email service
func NewService(
	config *EmailConfig,
	templates TemplateRepository,
	queue QueueRepository,
	analytics AnalyticsRepository,
	logger *slog.Logger,
) (*Service, error) {
	s := &Service{
		config:    config,
		providers: make(map[string]Provider),
		templates: templates,
		queue:     queue,
		analytics: analytics,
		logger:    logger,
	}

	// Initialize providers
	if err := s.initializeProviders(); err != nil {
		return nil, fmt.Errorf("failed to initialize providers: %w", err)
	}

	// Initialize default templates
	if err := s.initializeDefaultTemplates(context.Background()); err != nil {
		s.logger.Warn("Failed to initialize default templates", "error", err)
	}

	return s, nil
}

// SendEmail sends a single email
func (s *Service) SendEmail(ctx context.Context, req *interfaces.SendEmailRequest) error {
	// Validate request
	if err := s.validateEmailRequest(req); err != nil {
		return fmt.Errorf("invalid email request: %w", err)
	}

	// Generate email ID
	emailID := uuid.New().String()
	req.Metadata = s.ensureMetadata(req.Metadata)
	req.Metadata["email_id"] = emailID

	// Process template if specified
	if req.TemplateID != "" {
		if err := s.processTemplate(ctx, req); err != nil {
			return fmt.Errorf("failed to process template: %w", err)
		}
	}

	// Queue email for sending
	queueItem := &interfaces.EmailQueue{
		ID:          emailID,
		Request:     req,
		Status:      interfaces.StatusPending,
		Provider:    s.config.DefaultProvider,
		Attempts:    0,
		MaxAttempts: s.config.Retry.MaxRetries,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := s.queue.Enqueue(ctx, queueItem); err != nil {
		return fmt.Errorf("failed to queue email: %w", err)
	}

	// Send immediately if not using queue
	return s.sendEmailNow(ctx, queueItem)
}

// SendBulkEmails sends multiple emails
func (s *Service) SendBulkEmails(ctx context.Context, req *BulkEmailRequest) error {
	if len(req.Emails) == 0 {
		return fmt.Errorf("no emails to send")
	}

	batchSize := req.BatchSize
	if batchSize <= 0 {
		batchSize = 10 // Default batch size
	}

	for i := 0; i < len(req.Emails); i += batchSize {
		end := i + batchSize
		if end > len(req.Emails) {
			end = len(req.Emails)
		}

		batch := req.Emails[i:end]
		for _, email := range batch {
			if err := s.SendEmail(ctx, email); err != nil {
				s.logger.Error("Failed to send email in bulk", "error", err)
			}
		}

		// Delay between batches
		if req.DelayBetween > 0 && end < len(req.Emails) {
			time.Sleep(req.DelayBetween)
		}
	}

	return nil
}

// Pre-made template methods
func (s *Service) SendWelcomeEmail(ctx context.Context, to, name string) error {
	return s.SendEmail(ctx, &interfaces.SendEmailRequest{
		To:         []string{to},
		TemplateID: DefaultPrebuiltTemplates().Welcome,
		Variables: map[string]string{
			"name": name,
		},
	})
}

func (s *Service) SendVerificationEmail(ctx context.Context, to, name, token string) error {
	return s.SendEmail(ctx, &interfaces.SendEmailRequest{
		To:         []string{to},
		TemplateID: DefaultPrebuiltTemplates().Verification,
		Variables: map[string]string{
			"name":             name,
			"token":            token,
			"verification_url": fmt.Sprintf("%s/verify?token=%s", s.config.Templates.BaseURL, token),
		},
	})
}

func (s *Service) SendPasswordResetEmail(ctx context.Context, to, name, token string) error {
	return s.SendEmail(ctx, &interfaces.SendEmailRequest{
		To:         []string{to},
		TemplateID: DefaultPrebuiltTemplates().PasswordReset,
		Variables: map[string]string{
			"name":      name,
			"token":     token,
			"reset_url": fmt.Sprintf("%s/reset-password?token=%s", s.config.Templates.BaseURL, token),
		},
	})
}

func (s *Service) SendLoginNotificationEmail(ctx context.Context, to, name, location, device string) error {
	return s.SendEmail(ctx, &interfaces.SendEmailRequest{
		To:         []string{to},
		TemplateID: DefaultPrebuiltTemplates().LoginNotification,
		Variables: map[string]string{
			"name":     name,
			"location": location,
			"device":   device,
			"time":     time.Now().Format("January 2, 2006 at 3:04 PM"),
		},
	})
}

func (s *Service) SendMFACodeEmail(ctx context.Context, to, name, code string) error {
	return s.SendEmail(ctx, &interfaces.SendEmailRequest{
		To:         []string{to},
		TemplateID: DefaultPrebuiltTemplates().MFACode,
		Variables: map[string]string{
			"name": name,
			"code": code,
		},
	})
}

func (s *Service) SendAccountLockedEmail(ctx context.Context, to, name string) error {
	return s.SendEmail(ctx, &interfaces.SendEmailRequest{
		To:         []string{to},
		TemplateID: DefaultPrebuiltTemplates().AccountLocked,
		Variables: map[string]string{
			"name": name,
		},
	})
}

func (s *Service) SendPasswordChangedEmail(ctx context.Context, to, name string) error {
	return s.SendEmail(ctx, &interfaces.SendEmailRequest{
		To:         []string{to},
		TemplateID: DefaultPrebuiltTemplates().PasswordChanged,
		Variables: map[string]string{
			"name": name,
		},
	})
}

// Template management methods
func (s *Service) CreateTemplate(ctx context.Context, template *EmailTemplate) error {
	template.ID = uuid.New().String()
	template.CreatedAt = time.Now()
	template.UpdatedAt = time.Now()

	return s.templates.Create(ctx, template)
}

func (s *Service) UpdateTemplate(ctx context.Context, id string, template *EmailTemplate) error {
	template.ID = id
	template.UpdatedAt = time.Now()

	return s.templates.Update(ctx, template)
}

func (s *Service) GetTemplate(ctx context.Context, id string) (*EmailTemplate, error) {
	return s.templates.GetByID(ctx, id)
}

func (s *Service) DeleteTemplate(ctx context.Context, id string) error {
	return s.templates.Delete(ctx, id)
}

func (s *Service) ListTemplates(ctx context.Context, filter *TemplateFilter) ([]*EmailTemplate, error) {
	return s.templates.List(ctx, filter)
}

// Email tracking and analytics
func (s *Service) GetEmailStatus(ctx context.Context, emailID string) (*EmailStatus, error) {
	return s.analytics.GetEmailStatus(ctx, emailID)
}

func (s *Service) GetEmailAnalytics(ctx context.Context, filter *AnalyticsFilter) (*EmailAnalytics, error) {
	return s.analytics.GetAnalytics(ctx, filter)
}

// Health check
func (s *Service) HealthCheck(ctx context.Context) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for name, provider := range s.providers {
		if err := provider.HealthCheck(ctx); err != nil {
			return fmt.Errorf("provider %s health check failed: %w", name, err)
		}
	}

	return nil
}

// Private methods

func (s *Service) initializeProviders() error {
	for name, config := range s.config.Providers {
		if !config.Enabled {
			continue
		}

		provider, err := s.createProvider(name, &config)
		if err != nil {
			return fmt.Errorf("failed to create provider %s: %w", name, err)
		}

		s.providers[name] = provider
	}

	if len(s.providers) == 0 {
		return fmt.Errorf("no email providers configured")
	}

	return nil
}

func (s *Service) createProvider(name string, config *ProviderConfig) (Provider, error) {
	switch config.Type {
	case interfaces.ProviderSMTP:
		return NewSMTPProvider(config.SMTP)
	case interfaces.ProviderSendGrid:
		return NewSendGridProvider(config.SendGrid)
	case interfaces.ProviderMailgun:
		return NewMailgunProvider(config.Mailgun)
	case interfaces.ProviderSES:
		return NewSESProvider(config.SES)
	case interfaces.ProviderPostmark:
		return NewPostmarkProvider(config.Postmark)
	case interfaces.ProviderResend:
		return NewResendProvider(config.Resend)
	default:
		return nil, fmt.Errorf("unsupported provider type: %s", config.Type)
	}
}

func (s *Service) validateEmailRequest(req *interfaces.SendEmailRequest) error {
	if len(req.To) == 0 {
		return fmt.Errorf("no recipients specified")
	}

	if req.Subject == "" && req.TemplateID == "" {
		return fmt.Errorf("subject or template ID required")
	}

	if req.HTMLBody == "" && req.TextBody == "" && req.TemplateID == "" {
		return fmt.Errorf("email body or template ID required")
	}

	return nil
}

func (s *Service) processTemplate(ctx context.Context, req *interfaces.SendEmailRequest) error {
	template, err := s.templates.GetByID(ctx, req.TemplateID)
	if err != nil {
		return fmt.Errorf("template not found: %w", err)
	}

	if !template.IsActive {
		return fmt.Errorf("template is not active")
	}

	// Replace variables in subject and body
	req.Subject = s.replaceVariables(template.Subject, req.Variables)
	req.HTMLBody = s.replaceVariables(template.HTMLBody, req.Variables)
	if template.TextBody != "" {
		req.TextBody = s.replaceVariables(template.TextBody, req.Variables)
	}

	return nil
}

func (s *Service) replaceVariables(content string, variables map[string]string) string {
	result := content
	for key, value := range variables {
		placeholder := fmt.Sprintf("{{%s}}", key)
		result = strings.ReplaceAll(result, placeholder, value)
	}
	return result
}

func (s *Service) ensureMetadata(metadata map[string]string) map[string]string {
	if metadata == nil {
		metadata = make(map[string]string)
	}
	return metadata
}

func (s *Service) sendEmailNow(ctx context.Context, queueItem *interfaces.EmailQueue) error {
	provider, exists := s.providers[string(queueItem.Provider)]
	if !exists {
		// Fallback to default provider
		for _, p := range s.providers {
			provider = p
			break
		}
	}

	if provider == nil {
		return fmt.Errorf("no email provider available")
	}

	err := provider.SendEmail(ctx, queueItem.Request)
	if err != nil {
		queueItem.Status = interfaces.StatusFailed
		queueItem.Error = err.Error()
		queueItem.Attempts++
		queueItem.UpdatedAt = time.Now()

		// Schedule retry if configured
		if s.config.Retry.Enabled && queueItem.Attempts < queueItem.MaxAttempts {
			nextRetry := time.Now().Add(s.calculateRetryDelay(queueItem.Attempts))
			queueItem.NextRetry = &nextRetry
			queueItem.Status = interfaces.StatusPending
		}

		s.queue.Update(ctx, queueItem)
		return err
	}

	queueItem.Status = interfaces.StatusSent
	queueItem.UpdatedAt = time.Now()
	s.queue.Update(ctx, queueItem)

	return nil
}

func (s *Service) calculateRetryDelay(attempt int) time.Duration {
	delay := s.config.Retry.InitialDelay
	for i := 0; i < attempt; i++ {
		delay = time.Duration(float64(delay) * s.config.Retry.Multiplier)
		if delay > s.config.Retry.MaxDelay {
			delay = s.config.Retry.MaxDelay
			break
		}
	}
	return delay
}
