package providers

import (
	"context"
	"fmt"

	"github.com/steve-mir/go-auth-system/internal/service/email"
)

// ResendProvider implements email sending via Resend API
type ResendProvider struct {
	config *email.ResendConfig
}

// NewResendProvider creates a new Resend provider
func NewResendProvider(config *email.ResendConfig) (*ResendProvider, error) {
	if config == nil || config.APIKey == "" {
		return nil, fmt.Errorf("Resend API key is required")
	}

	return &ResendProvider{
		config: config,
	}, nil
}

// SendEmail sends an email via Resend API
func (p *ResendProvider) SendEmail(ctx context.Context, req *email.SendEmailRequest) error {
	// TODO: Implement Resend API integration
	return fmt.Errorf("Resend provider not yet implemented")
}

// HealthCheck checks if Resend API is accessible
func (p *ResendProvider) HealthCheck(ctx context.Context) error {
	// TODO: Implement Resend health check
	return nil
}

// GetName returns the provider name
func (p *ResendProvider) GetName() string {
	return "Resend"
}

// GetType returns the provider type
func (p *ResendProvider) GetType() email.EmailProvider {
	return email.ProviderResend
}
