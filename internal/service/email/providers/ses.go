package providers

import (
	"context"
	"fmt"

	"github.com/steve-mir/go-auth-system/internal/service/email"
)

// SESProvider implements email sending via AWS SES
type SESProvider struct {
	config *email.SESConfig
}

// NewSESProvider creates a new AWS SES provider
func NewSESProvider(config *email.SESConfig) (*SESProvider, error) {
	if config == nil || config.Region == "" {
		return nil, fmt.Errorf("AWS SES region is required")
	}

	return &SESProvider{
		config: config,
	}, nil
}

// SendEmail sends an email via AWS SES
func (p *SESProvider) SendEmail(ctx context.Context, req *email.SendEmailRequest) error {
	// TODO: Implement AWS SES integration
	return fmt.Errorf("AWS SES provider not yet implemented")
}

// HealthCheck checks if AWS SES is accessible
func (p *SESProvider) HealthCheck(ctx context.Context) error {
	// TODO: Implement AWS SES health check
	return nil
}

// GetName returns the provider name
func (p *SESProvider) GetName() string {
	return "AWS SES"
}

// GetType returns the provider type
func (p *SESProvider) GetType() email.EmailProvider {
	return email.ProviderSES
}
