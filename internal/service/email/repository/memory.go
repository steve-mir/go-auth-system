package repository

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/steve-mir/go-auth-system/internal/service/email"
)

// MemoryTemplateRepository implements TemplateRepository using in-memory storage
type MemoryTemplateRepository struct {
	templates map[string]*email.EmailTemplate
	mu        sync.RWMutex
}

// NewMemoryTemplateRepository creates a new in-memory template repository
func NewMemoryTemplateRepository() *MemoryTemplateRepository {
	return &MemoryTemplateRepository{
		templates: make(map[string]*email.EmailTemplate),
	}
}

// Create creates a new email template
func (r *MemoryTemplateRepository) Create(ctx context.Context, template *email.EmailTemplate) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.templates[template.ID]; exists {
		return fmt.Errorf("template with ID %s already exists", template.ID)
	}

	r.templates[template.ID] = template
	return nil
}

// Update updates an existing email template
func (r *MemoryTemplateRepository) Update(ctx context.Context, template *email.EmailTemplate) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.templates[template.ID]; !exists {
		return email.ErrTemplateNotFound
	}

	r.templates[template.ID] = template
	return nil
}

// GetByID retrieves a template by ID
func (r *MemoryTemplateRepository) GetByID(ctx context.Context, id string) (*email.EmailTemplate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	template, exists := r.templates[id]
	if !exists {
		return nil, email.ErrTemplateNotFound
	}

	return template, nil
}

// Delete deletes a template by ID
func (r *MemoryTemplateRepository) Delete(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.templates[id]; !exists {
		return email.ErrTemplateNotFound
	}

	delete(r.templates, id)
	return nil
}

// List lists templates with optional filtering
func (r *MemoryTemplateRepository) List(ctx context.Context, filter *email.TemplateFilter) ([]*email.EmailTemplate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*email.EmailTemplate

	for _, template := range r.templates {
		if r.matchesFilter(template, filter) {
			result = append(result, template)
		}
	}

	// Apply pagination
	if filter != nil {
		if filter.Offset > 0 && filter.Offset < len(result) {
			result = result[filter.Offset:]
		}
		if filter.Limit > 0 && filter.Limit < len(result) {
			result = result[:filter.Limit]
		}
	}

	return result, nil
}

func (r *MemoryTemplateRepository) matchesFilter(template *email.EmailTemplate, filter *email.TemplateFilter) bool {
	if filter == nil {
		return true
	}

	// Category filter
	if filter.Category != "" && template.Category != filter.Category {
		return false
	}

	// Active filter
	if filter.IsActive != nil && template.IsActive != *filter.IsActive {
		return false
	}

	// Tags filter
	if len(filter.Tags) > 0 {
		hasTag := false
		for _, filterTag := range filter.Tags {
			for _, templateTag := range template.Tags {
				if templateTag == filterTag {
					hasTag = true
					break
				}
			}
			if hasTag {
				break
			}
		}
		if !hasTag {
			return false
		}
	}

	// Search filter
	if filter.Search != "" {
		searchLower := strings.ToLower(filter.Search)
		if !strings.Contains(strings.ToLower(template.Name), searchLower) &&
			!strings.Contains(strings.ToLower(template.Description), searchLower) &&
			!strings.Contains(strings.ToLower(template.Subject), searchLower) {
			return false
		}
	}

	return true
}

// MemoryQueueRepository implements QueueRepository using in-memory storage
type MemoryQueueRepository struct {
	queue map[string]*email.EmailQueue
	mu    sync.RWMutex
}

// NewMemoryQueueRepository creates a new in-memory queue repository
func NewMemoryQueueRepository() *MemoryQueueRepository {
	return &MemoryQueueRepository{
		queue: make(map[string]*email.EmailQueue),
	}
}

// Enqueue adds an email to the queue
func (r *MemoryQueueRepository) Enqueue(ctx context.Context, emailQueue *email.EmailQueue) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.queue[emailQueue.ID] = emailQueue
	return nil
}

// Dequeue retrieves emails from the queue
func (r *MemoryQueueRepository) Dequeue(ctx context.Context, limit int) ([]*email.EmailQueue, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*email.EmailQueue
	count := 0

	for _, emailQueue := range r.queue {
		if emailQueue.Status == email.StatusPending && count < limit {
			result = append(result, emailQueue)
			count++
		}
	}

	return result, nil
}

// Update updates an email in the queue
func (r *MemoryQueueRepository) Update(ctx context.Context, emailQueue *email.EmailQueue) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.queue[emailQueue.ID]; !exists {
		return fmt.Errorf("email queue item not found")
	}

	r.queue[emailQueue.ID] = emailQueue
	return nil
}

// Delete removes an email from the queue
func (r *MemoryQueueRepository) Delete(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.queue[id]; !exists {
		return fmt.Errorf("email queue item not found")
	}

	delete(r.queue, id)
	return nil
}

// GetByID retrieves an email from the queue by ID
func (r *MemoryQueueRepository) GetByID(ctx context.Context, id string) (*email.EmailQueue, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	emailQueue, exists := r.queue[id]
	if !exists {
		return nil, fmt.Errorf("email queue item not found")
	}

	return emailQueue, nil
}

// GetPendingRetries retrieves emails that are ready for retry
func (r *MemoryQueueRepository) GetPendingRetries(ctx context.Context) ([]*email.EmailQueue, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*email.EmailQueue
	now := time.Now()

	for _, emailQueue := range r.queue {
		if emailQueue.Status == email.StatusPending &&
			emailQueue.NextRetry != nil &&
			emailQueue.NextRetry.Before(now) {
			result = append(result, emailQueue)
		}
	}

	return result, nil
}

// MemoryAnalyticsRepository implements AnalyticsRepository using in-memory storage
type MemoryAnalyticsRepository struct {
	statuses map[string]*email.EmailStatus
	logs     map[string][]*email.EmailLog
	mu       sync.RWMutex
}

// NewMemoryAnalyticsRepository creates a new in-memory analytics repository
func NewMemoryAnalyticsRepository() *MemoryAnalyticsRepository {
	return &MemoryAnalyticsRepository{
		statuses: make(map[string]*email.EmailStatus),
		logs:     make(map[string][]*email.EmailLog),
	}
}

// RecordEmailSent records that an email was sent
func (r *MemoryAnalyticsRepository) RecordEmailSent(ctx context.Context, emailID string, metadata map[string]string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	r.statuses[emailID] = &email.EmailStatus{
		ID:       emailID,
		Status:   email.StatusSent,
		SentAt:   &now,
		Metadata: metadata,
	}

	return nil
}

// RecordEmailDelivered records that an email was delivered
func (r *MemoryAnalyticsRepository) RecordEmailDelivered(ctx context.Context, emailID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if status, exists := r.statuses[emailID]; exists {
		now := time.Now()
		status.Status = email.StatusDelivered
		status.DeliveredAt = &now
	}

	return nil
}

// RecordEmailOpened records that an email was opened
func (r *MemoryAnalyticsRepository) RecordEmailOpened(ctx context.Context, emailID string, userAgent, ipAddress string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if status, exists := r.statuses[emailID]; exists {
		now := time.Now()
		status.Status = email.StatusOpened
		status.OpenedAt = &now
	}

	return nil
}

// RecordEmailClicked records that an email link was clicked
func (r *MemoryAnalyticsRepository) RecordEmailClicked(ctx context.Context, emailID string, url, userAgent, ipAddress string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if status, exists := r.statuses[emailID]; exists {
		now := time.Now()
		status.Status = email.StatusClicked
		status.ClickedAt = &now
	}

	return nil
}

// RecordEmailBounced records that an email bounced
func (r *MemoryAnalyticsRepository) RecordEmailBounced(ctx context.Context, emailID string, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if status, exists := r.statuses[emailID]; exists {
		now := time.Now()
		status.Status = email.StatusBounced
		status.BouncedAt = &now
		status.Error = reason
	}

	return nil
}

// GetEmailStatus retrieves the status of an email
func (r *MemoryAnalyticsRepository) GetEmailStatus(ctx context.Context, emailID string) (*email.EmailStatus, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	status, exists := r.statuses[emailID]
	if !exists {
		return nil, fmt.Errorf("email status not found")
	}

	return status, nil
}

// GetAnalytics retrieves email analytics
func (r *MemoryAnalyticsRepository) GetAnalytics(ctx context.Context, filter *email.AnalyticsFilter) (*email.EmailAnalytics, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	analytics := &email.EmailAnalytics{}

	for _, status := range r.statuses {
		if r.matchesAnalyticsFilter(status, filter) {
			analytics.TotalSent++

			switch status.Status {
			case email.StatusDelivered, email.StatusOpened, email.StatusClicked:
				analytics.TotalDelivered++
			case email.StatusOpened, email.StatusClicked:
				analytics.TotalOpened++
			case email.StatusClicked:
				analytics.TotalClicked++
			case email.StatusBounced:
				analytics.TotalBounced++
			}
		}
	}

	// Calculate rates
	if analytics.TotalSent > 0 {
		analytics.DeliveryRate = float64(analytics.TotalDelivered) / float64(analytics.TotalSent)
		analytics.BounceRate = float64(analytics.TotalBounced) / float64(analytics.TotalSent)
	}

	if analytics.TotalDelivered > 0 {
		analytics.OpenRate = float64(analytics.TotalOpened) / float64(analytics.TotalDelivered)
	}

	if analytics.TotalOpened > 0 {
		analytics.ClickRate = float64(analytics.TotalClicked) / float64(analytics.TotalOpened)
	}

	return analytics, nil
}

func (r *MemoryAnalyticsRepository) matchesAnalyticsFilter(status *email.EmailStatus, filter *email.AnalyticsFilter) bool {
	if filter == nil {
		return true
	}

	// Time range filter
	if status.SentAt != nil {
		if status.SentAt.Before(filter.From) || status.SentAt.After(filter.To) {
			return false
		}
	}

	// Additional filters can be added here based on metadata

	return true
}
