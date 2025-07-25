package email

import (
	"context"
	"time"

	"github.com/steve-mir/go-auth-system/internal/interfaces"
)

// StubTemplateRepository is a stub implementation of TemplateRepository
type StubTemplateRepository struct {
	templates map[string]*EmailTemplate
}

// NewStubTemplateRepository creates a new stub template repository
func NewStubTemplateRepository() TemplateRepository {
	return &StubTemplateRepository{
		templates: make(map[string]*EmailTemplate),
	}
}

// Create creates a new email template
func (r *StubTemplateRepository) Create(ctx context.Context, template *EmailTemplate) error {
	r.templates[template.ID] = template
	return nil
}

// Update updates an existing email template
func (r *StubTemplateRepository) Update(ctx context.Context, template *EmailTemplate) error {
	r.templates[template.ID] = template
	return nil
}

// GetByID retrieves a template by ID
func (r *StubTemplateRepository) GetByID(ctx context.Context, id string) (*EmailTemplate, error) {
	template, exists := r.templates[id]
	if !exists {
		return nil, interfaces.ErrTemplateNotFound
	}
	return template, nil
}

// Delete deletes a template
func (r *StubTemplateRepository) Delete(ctx context.Context, id string) error {
	delete(r.templates, id)
	return nil
}

// List lists templates with filtering
func (r *StubTemplateRepository) List(ctx context.Context, filter *TemplateFilter) ([]*EmailTemplate, error) {
	var templates []*EmailTemplate
	for _, template := range r.templates {
		templates = append(templates, template)
	}
	return templates, nil
}

// StubQueueRepository is a stub implementation of QueueRepository
type StubQueueRepository struct {
	queue map[string]*interfaces.EmailQueue
}

// NewStubQueueRepository creates a new stub queue repository
func NewStubQueueRepository() QueueRepository {
	return &StubQueueRepository{
		queue: make(map[string]*interfaces.EmailQueue),
	}
}

// Enqueue adds an email to the queue
func (r *StubQueueRepository) Enqueue(ctx context.Context, email *interfaces.EmailQueue) error {
	r.queue[email.ID] = email
	return nil
}

// Dequeue retrieves the next emails from the queue
func (r *StubQueueRepository) Dequeue(ctx context.Context, limit int) ([]*interfaces.EmailQueue, error) {
	var pending []*interfaces.EmailQueue
	count := 0
	for _, email := range r.queue {
		if email.Status == interfaces.StatusPending && count < limit {
			pending = append(pending, email)
			count++
		}
	}
	return pending, nil
}

// Update updates an email in the queue
func (r *StubQueueRepository) Update(ctx context.Context, email *interfaces.EmailQueue) error {
	r.queue[email.ID] = email
	return nil
}

// Delete removes an email from the queue
func (r *StubQueueRepository) Delete(ctx context.Context, id string) error {
	delete(r.queue, id)
	return nil
}

// GetByID retrieves an email by ID
func (r *StubQueueRepository) GetByID(ctx context.Context, id string) (*interfaces.EmailQueue, error) {
	email, exists := r.queue[id]
	if !exists {
		return nil, nil
	}
	return email, nil
}

// GetPendingRetries retrieves emails that need to be retried
func (r *StubQueueRepository) GetPendingRetries(ctx context.Context) ([]*interfaces.EmailQueue, error) {
	var retries []*interfaces.EmailQueue
	now := time.Now()
	for _, email := range r.queue {
		if email.Status == interfaces.StatusPending && email.NextRetry != nil && email.NextRetry.Before(now) {
			retries = append(retries, email)
		}
	}
	return retries, nil
}

// StubAnalyticsRepository is a stub implementation of AnalyticsRepository
type StubAnalyticsRepository struct {
	statuses  map[string]*EmailStatus
	analytics *EmailAnalytics
}

// NewStubAnalyticsRepository creates a new stub analytics repository
func NewStubAnalyticsRepository() AnalyticsRepository {
	return &StubAnalyticsRepository{
		statuses: make(map[string]*EmailStatus),
		analytics: &EmailAnalytics{
			TotalSent: 0,
			// TotalFailed:   0,
			DeliveryRate: 100.0,
			OpenRate:     25.0,
			ClickRate:    5.0,
			BounceRate:   2.0,
			// ComplaintRate: 0.1,
		},
	}
}

// RecordEmailSent records that an email was sent
func (r *StubAnalyticsRepository) RecordEmailSent(ctx context.Context, emailID string, metadata map[string]string) error {
	now := time.Now()
	r.statuses[emailID] = &EmailStatus{
		ID:          emailID,
		Status:      interfaces.StatusSent,
		SentAt:      &now,
		DeliveredAt: nil,
		OpenedAt:    nil,
		ClickedAt:   nil,
		BouncedAt:   nil,
		// ComplainedAt: nil,
		// Events:       []interfaces.EmailEvent{},
	}
	return nil
}

// RecordEmailDelivered records that an email was delivered
func (r *StubAnalyticsRepository) RecordEmailDelivered(ctx context.Context, emailID string) error {
	if status, exists := r.statuses[emailID]; exists {
		now := time.Now()
		status.Status = interfaces.StatusDelivered
		status.DeliveredAt = &now
	}
	return nil
}

// RecordEmailOpened records that an email was opened
func (r *StubAnalyticsRepository) RecordEmailOpened(ctx context.Context, emailID string, userAgent, ipAddress string) error {
	if status, exists := r.statuses[emailID]; exists {
		now := time.Now()
		status.Status = interfaces.StatusOpened
		status.OpenedAt = &now
	}
	return nil
}

// RecordEmailClicked records that an email was clicked
func (r *StubAnalyticsRepository) RecordEmailClicked(ctx context.Context, emailID string, url, userAgent, ipAddress string) error {
	if status, exists := r.statuses[emailID]; exists {
		now := time.Now()
		status.Status = interfaces.StatusClicked
		status.ClickedAt = &now
	}
	return nil
}

// RecordEmailBounced records that an email bounced
func (r *StubAnalyticsRepository) RecordEmailBounced(ctx context.Context, emailID string, reason string) error {
	if status, exists := r.statuses[emailID]; exists {
		now := time.Now()
		status.Status = interfaces.StatusBounced
		status.BouncedAt = &now
	}
	return nil
}

// GetEmailStatus retrieves email status
func (r *StubAnalyticsRepository) GetEmailStatus(ctx context.Context, emailID string) (*EmailStatus, error) {
	status, exists := r.statuses[emailID]
	if !exists {
		return nil, nil
	}
	return status, nil
}

// GetAnalytics retrieves email analytics
func (r *StubAnalyticsRepository) GetAnalytics(ctx context.Context, filter *AnalyticsFilter) (*EmailAnalytics, error) {
	return r.analytics, nil
}
