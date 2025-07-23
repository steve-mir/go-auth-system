package providers

import (
	"context"
	"fmt"

	"github.com/steve-mir/go-auth-system/internal/service/email"
)

// PostmarkProvider implements email sending via Postmark API
type PostmarkProvider struct {
	config *email.PostmarkConfig
}

// NewPostmarkProvider creates a new Postmark provider
func NewPostmarkProvider(config *email.PostmarkConfig) (*PostmarkProvider, error) {
	if config == nil || config.APIKey == "" {
		return nil, fmt.Errorf("Postmark API key is required")
	}

	return &PostmarkProvider{
		config: config,
	}, nil
}

// SendEmail sends an email via Postmark API
func (p *PostmarkProvider) SendEmail(ctx context.Context, req *email.SendEmailRequest) error {
	// TODO: Implement Postmark API integration
	return fmt.Errorf("Postmark provider not yet implemented")
}

// HealthCheck checks if Postmark API is accessible
func (p *PostmarkProvider) HealthCheck(ctx context.Context) error {
	// TODO: Implement Postmark health check
	return nil
}

// GetName returns the provider name
func (p *PostmarkProvider) GetName() string {
	return "Postmark"
}

// GetType returns the provider type
func (p *PostmarkProvider) GetType() email.EmailProvider {
	return email.ProviderPostmark
}
