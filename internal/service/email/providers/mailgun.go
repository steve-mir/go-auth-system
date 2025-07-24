package providers

import (
	"context"
	"fmt"

	"github.com/steve-mir/go-auth-system/internal/interfaces"
)

// MailgunProvider implements email sending via Mailgun API
type MailgunProvider struct {
	config *interfaces.MailgunConfig
}

// NewMailgunProvider creates a new Mailgun provider
func NewMailgunProvider(config *interfaces.MailgunConfig) (*MailgunProvider, error) {
	if config == nil || config.APIKey == "" {
		return nil, fmt.Errorf("Mailgun API key is required")
	}

	return &MailgunProvider{
		config: config,
	}, nil
}

// SendEmail sends an email via Mailgun API
func (p *MailgunProvider) SendEmail(ctx context.Context, req *interfaces.SendEmailRequest) error {
	// TODO: Implement Mailgun API integration
	return fmt.Errorf("Mailgun provider not yet implemented")
}

// HealthCheck checks if Mailgun API is accessible
func (p *MailgunProvider) HealthCheck(ctx context.Context) error {
	// TODO: Implement Mailgun health check
	return nil
}

// GetName returns the provider name
func (p *MailgunProvider) GetName() string {
	return "Mailgun"
}

// GetType returns the provider type
func (p *MailgunProvider) GetType() interfaces.EmailProvider {
	return interfaces.ProviderMailgun
}
