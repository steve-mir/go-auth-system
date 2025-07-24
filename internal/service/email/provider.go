package email

import (
	"context"

	"github.com/steve-mir/go-auth-system/internal/interfaces"
)

// Provider defines the interface for email providers
type Provider interface {
	SendEmail(ctx context.Context, req *interfaces.SendEmailRequest) error
	HealthCheck(ctx context.Context) error
	GetName() string
	GetType() interfaces.EmailProvider
}

// TemplateRepository defines the interface for template storage
type TemplateRepository interface {
	Create(ctx context.Context, template *EmailTemplate) error
	Update(ctx context.Context, template *EmailTemplate) error
	GetByID(ctx context.Context, id string) (*EmailTemplate, error)
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, filter *TemplateFilter) ([]*EmailTemplate, error)
}

// QueueRepository defines the interface for email queue storage
type QueueRepository interface {
	Enqueue(ctx context.Context, email *interfaces.EmailQueue) error
	Dequeue(ctx context.Context, limit int) ([]*interfaces.EmailQueue, error)
	Update(ctx context.Context, email *interfaces.EmailQueue) error
	Delete(ctx context.Context, id string) error
	GetByID(ctx context.Context, id string) (*interfaces.EmailQueue, error)
	GetPendingRetries(ctx context.Context) ([]*interfaces.EmailQueue, error)
}

// AnalyticsRepository defines the interface for email analytics storage
type AnalyticsRepository interface {
	RecordEmailSent(ctx context.Context, emailID string, metadata map[string]string) error
	RecordEmailDelivered(ctx context.Context, emailID string) error
	RecordEmailOpened(ctx context.Context, emailID string, userAgent, ipAddress string) error
	RecordEmailClicked(ctx context.Context, emailID string, url, userAgent, ipAddress string) error
	RecordEmailBounced(ctx context.Context, emailID string, reason string) error
	GetEmailStatus(ctx context.Context, emailID string) (*EmailStatus, error)
	GetAnalytics(ctx context.Context, filter *AnalyticsFilter) (*EmailAnalytics, error)
}
