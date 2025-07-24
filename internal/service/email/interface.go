package email

import (
	"context"
	"time"

	"github.com/steve-mir/go-auth-system/internal/interfaces"
)

// EmailService defines the interface for email operations
type EmailService interface {
	// Send a single email
	SendEmail(ctx context.Context, req *SendEmailRequest) error

	// Send bulk emails
	SendBulkEmails(ctx context.Context, req *BulkEmailRequest) error

	// Pre-made template methods
	SendWelcomeEmail(ctx context.Context, to, name string) error
	SendVerificationEmail(ctx context.Context, to, name, token string) error
	SendPasswordResetEmail(ctx context.Context, to, name, token string) error
	SendLoginNotificationEmail(ctx context.Context, to, name, location, device string) error
	SendMFACodeEmail(ctx context.Context, to, name, code string) error
	SendAccountLockedEmail(ctx context.Context, to, name string) error
	SendPasswordChangedEmail(ctx context.Context, to, name string) error

	// Template management
	CreateTemplate(ctx context.Context, template *EmailTemplate) error
	UpdateTemplate(ctx context.Context, id string, template *EmailTemplate) error
	GetTemplate(ctx context.Context, id string) (*EmailTemplate, error)
	DeleteTemplate(ctx context.Context, id string) error
	ListTemplates(ctx context.Context, filter *TemplateFilter) ([]*EmailTemplate, error)

	// Email tracking and analytics
	GetEmailStatus(ctx context.Context, emailID string) (*EmailStatus, error)
	GetEmailAnalytics(ctx context.Context, filter *AnalyticsFilter) (*EmailAnalytics, error)

	// Health check
	HealthCheck(ctx context.Context) error
}

// SendEmailRequest represents a single email request
type SendEmailRequest struct {
	To          []string           `json:"to"`
	CC          []string           `json:"cc,omitempty"`
	BCC         []string           `json:"bcc,omitempty"`
	From        string             `json:"from,omitempty"`
	FromName    string             `json:"from_name,omitempty"`
	Subject     string             `json:"subject"`
	HTMLBody    string             `json:"html_body,omitempty"`
	TextBody    string             `json:"text_body,omitempty"`
	TemplateID  string             `json:"template_id,omitempty"`
	Variables   map[string]string  `json:"variables,omitempty"`
	Attachments []*EmailAttachment `json:"attachments,omitempty"`
	Priority    EmailPriority      `json:"priority,omitempty"`
	Tags        []string           `json:"tags,omitempty"`
	Metadata    map[string]string  `json:"metadata,omitempty"`
}

// BulkEmailRequest represents a bulk email request
type BulkEmailRequest struct {
	Emails       []*interfaces.SendEmailRequest `json:"emails"`
	BatchSize    int                            `json:"batch_size,omitempty"`
	DelayBetween time.Duration                  `json:"delay_between,omitempty"`
}

// EmailAttachment represents an email attachment
type EmailAttachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Content     []byte `json:"content"`
	Inline      bool   `json:"inline,omitempty"`
	ContentID   string `json:"content_id,omitempty"`
}

// EmailTemplate represents an email template
type EmailTemplate struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Subject     string    `json:"subject"`
	HTMLBody    string    `json:"html_body"`
	TextBody    string    `json:"text_body,omitempty"`
	Variables   []string  `json:"variables,omitempty"`
	Category    string    `json:"category,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	CreatedBy   string    `json:"created_by"`
	UpdatedBy   string    `json:"updated_by"`
}

// TemplateFilter represents filters for template queries
type TemplateFilter struct {
	Category string   `json:"category,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	IsActive *bool    `json:"is_active,omitempty"`
	Search   string   `json:"search,omitempty"`
	Limit    int      `json:"limit,omitempty"`
	Offset   int      `json:"offset,omitempty"`
}

// EmailStatus represents the status of a sent email
type EmailStatus struct {
	ID          string                    `json:"id"`
	Status      interfaces.DeliveryStatus `json:"status"`
	SentAt      *time.Time                `json:"sent_at,omitempty"`
	DeliveredAt *time.Time                `json:"delivered_at,omitempty"`
	OpenedAt    *time.Time                `json:"opened_at,omitempty"`
	ClickedAt   *time.Time                `json:"clicked_at,omitempty"`
	BouncedAt   *time.Time                `json:"bounced_at,omitempty"`
	Error       string                    `json:"error,omitempty"`
	Metadata    map[string]string         `json:"metadata,omitempty"`
}

// EmailAnalytics represents email analytics data
type EmailAnalytics struct {
	TotalSent      int64   `json:"total_sent"`
	TotalDelivered int64   `json:"total_delivered"`
	TotalOpened    int64   `json:"total_opened"`
	TotalClicked   int64   `json:"total_clicked"`
	TotalBounced   int64   `json:"total_bounced"`
	DeliveryRate   float64 `json:"delivery_rate"`
	OpenRate       float64 `json:"open_rate"`
	ClickRate      float64 `json:"click_rate"`
	BounceRate     float64 `json:"bounce_rate"`
}

// AnalyticsFilter represents filters for analytics queries
type AnalyticsFilter struct {
	From       time.Time `json:"from"`
	To         time.Time `json:"to"`
	TemplateID string    `json:"template_id,omitempty"`
	Tags       []string  `json:"tags,omitempty"`
	Category   string    `json:"category,omitempty"`
}

// EmailPriority represents email priority levels
type EmailPriority string

const (
	PriorityLow    EmailPriority = "low"
	PriorityNormal EmailPriority = "normal"
	PriorityHigh   EmailPriority = "high"
	PriorityUrgent EmailPriority = "urgent"
)

// // DeliveryStatus represents email delivery status
// type DeliveryStatus string

// const (
// 	StatusPending   DeliveryStatus = "pending"
// 	StatusSent      DeliveryStatus = "sent"
// 	StatusDelivered DeliveryStatus = "delivered"
// 	StatusOpened    DeliveryStatus = "opened"
// 	StatusClicked   DeliveryStatus = "clicked"
// 	StatusBounced   DeliveryStatus = "bounced"
// 	StatusFailed    DeliveryStatus = "failed"
// )
